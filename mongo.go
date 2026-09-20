package main

import (
	"context"
	"errors"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
)

// Store is the audit trail's durable replica in MongoDB Atlas. The local
// hash-chained file stays the source of truth; Atlas holds a queryable copy
// that anyone can re-verify, plus the decision and agent history the file
// cannot answer questions about ("every time this host was blocked, and why").
//
// Seals are written with $setOnInsert, so a replicated entry is never updated:
// the replica can gain history but not have it rewritten. Every write is
// asynchronous and best-effort - if Atlas is unreachable, verification and
// payment are unaffected, and the dashboard says the replica is behind.
type Store struct {
	uri  string
	work chan storeWrite

	mu        sync.Mutex
	client    *mongo.Client
	connected bool

	ledger, decisions, agents, anchors *mongo.Collection

	chain   string
	state   string
	writes  int
	dropped int
	lastErr string
}

// live returns the collections once a connection exists. Callers that need the
// database check ok rather than touching the fields directly, because the
// background writer may still be reconnecting.
func (s *Store) live() (ledger, decisions, agents, anchors *mongo.Collection, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ledger, s.decisions, s.agents, s.anchors, s.connected
}

// Chain is the seal of the ledger's genesis entry. Every replicated document
// carries it, so a laptop's ledger and the server's stay separate chains in one
// database instead of colliding on entry numbers.
func (s *Store) Chain() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.chain == "" {
		return "unknown"
	}
	return s.chain
}

// adoptChain records the genesis seal the first time it is replicated.
func (s *Store) adoptChain(entries []Entry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.chain != "" {
		return
	}
	for _, e := range entries {
		if e.Index == 0 {
			s.chain = e.Hash
			return
		}
	}
}

type storeWrite struct {
	name string
	run  func(context.Context) error
}

const mongoDatabase = "agentvouch"

// mongoCreds matches the userinfo in a connection string so a driver error can
// never carry the password into a log or an API reply.
var mongoCreds = regexp.MustCompile(`(mongodb(?:\+srv)?://)[^@\s/]*@`)

func safeMongoErr(err error) string {
	if err == nil {
		return ""
	}
	return mongoCreds.ReplaceAllString(err.Error(), "$1<redacted>@")
}

func mongoURI() string {
	if u := strings.TrimSpace(os.Getenv("MONGODB_URI")); u != "" {
		return u
	}
	if cd := os.Getenv("CREDENTIALS_DIRECTORY"); cd != "" {
		if b, err := os.ReadFile(filepath.Join(cd, "av_mongo.uri")); err == nil {
			return strings.TrimSpace(string(b))
		}
	}
	return ""
}

// mongoHost is the cluster address with the credentials stripped, safe to show.
func mongoHost(uri string) string {
	if i := strings.Index(uri, "@"); i >= 0 {
		uri = uri[i+1:]
	} else {
		uri = strings.TrimPrefix(strings.TrimPrefix(uri, "mongodb+srv://"), "mongodb://")
	}
	return strings.TrimSuffix(strings.SplitN(uri, "/", 2)[0], "?")
}

// newStore prepares the replica, or returns nil when no URI is configured
// (AgentVouch then runs on the local ledger alone). Connecting happens in Run:
// queued writes wait, and nothing else does.
func newStore() *Store {
	uri := mongoURI()
	if uri == "" {
		return nil
	}
	return &Store{uri: uri, work: make(chan storeWrite, 256), state: "connecting to " + mongoHost(uri)}
}

func (s *Store) connect(ctx context.Context) error {
	client, err := mongo.Connect(options.Client().ApplyURI(s.uri).
		SetAppName("agentvouch").
		SetServerSelectionTimeout(8 * time.Second).
		SetTimeout(15 * time.Second))
	if err != nil {
		return errors.New("mongodb: " + safeMongoErr(err))
	}
	if err := client.Ping(ctx, readpref.Primary()); err != nil {
		client.Disconnect(context.Background())
		return errors.New("mongodb ping: " + safeMongoErr(err))
	}
	db := client.Database(mongoDatabase)
	s.mu.Lock()
	s.client, s.connected = client, true
	s.ledger, s.decisions = db.Collection("ledger"), db.Collection("decisions")
	s.agents, s.anchors = db.Collection("agents"), db.Collection("anchors")
	s.state, s.lastErr = "connected to "+mongoHost(s.uri), ""
	s.mu.Unlock()
	s.ensureIndexes(ctx)
	log.Printf("mongodb atlas: replicating to %s/%s", mongoHost(s.uri), mongoDatabase)
	return nil
}

func (s *Store) ensureIndexes(ctx context.Context) {
	idx := map[*mongo.Collection][]mongo.IndexModel{
		s.ledger: {
			{Keys: bson.D{{Key: "chain", Value: 1}, {Key: "index", Value: 1}}},
			{Keys: bson.D{{Key: "event", Value: 1}, {Key: "time", Value: -1}}},
		},
		s.decisions: {
			{Keys: bson.D{{Key: "time", Value: -1}}},
			{Keys: bson.D{{Key: "chain", Value: 1}, {Key: "ok", Value: 1}}},
			{Keys: bson.D{{Key: "fqdn", Value: 1}, {Key: "ok", Value: 1}}},
			{Keys: bson.D{{Key: "runId", Value: 1}}},
		},
		s.anchors: {{Keys: bson.D{{Key: "chain", Value: 1}, {Key: "entries", Value: -1}}}},
		s.agents:  {{Keys: bson.D{{Key: "ansName", Value: 1}}}},
	}
	for coll, models := range idx {
		if _, err := coll.Indexes().CreateMany(ctx, models); err != nil {
			log.Printf("mongodb indexes on %s: %s", coll.Name(), safeMongoErr(err))
		}
	}
}

// Run connects, retrying until it succeeds, and then drains the write queue.
// One writer keeps the order of the chain. A cluster that starts unreachable -
// an IP that is not allow-listed yet, say - is picked up when it becomes
// reachable, without a restart and without the queued writes being lost.
func (s *Store) Run(ctx context.Context) {
	for {
		if _, _, _, _, ok := s.live(); !ok {
			cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
			err := s.connect(cctx)
			cancel()
			if err != nil {
				s.mu.Lock()
				s.state, s.lastErr = "unreachable: "+err.Error(), err.Error()
				s.mu.Unlock()
				log.Printf("mongodb atlas %v; retrying in 30s", err)
				select {
				case <-ctx.Done():
					return
				case <-time.After(30 * time.Second):
				}
				continue
			}
		}
		select {
		case <-ctx.Done():
			return
		case w := <-s.work:
			wctx, cancel := context.WithTimeout(ctx, 20*time.Second)
			err := w.run(wctx)
			cancel()
			s.mu.Lock()
			if err != nil {
				s.lastErr = w.name + ": " + safeMongoErr(err)
				if isNetworkError(err) {
					s.connected, s.state = false, "reconnecting: "+s.lastErr
				}
				log.Printf("mongodb %s", s.lastErr)
			} else {
				s.writes++
			}
			s.mu.Unlock()
		}
	}
}

// isNetworkError reports whether a failed write means the connection, rather
// than the document, was the problem.
func isNetworkError(err error) bool {
	return mongo.IsNetworkError(err) || mongo.IsTimeout(err) ||
		strings.Contains(err.Error(), "server selection error")
}

// enqueue hands a write to the background writer, and drops it if the queue is
// full. Nothing a payment decision does may wait on the database.
func (s *Store) enqueue(name string, run func(context.Context) error) {
	if s == nil {
		return
	}
	select {
	case s.work <- storeWrite{name, run}:
	default:
		s.mu.Lock()
		s.dropped++
		s.mu.Unlock()
	}
}

// MirrorLedger replicates entries. $setOnInsert means a seal already in Atlas
// is left exactly as it was first written.
func (s *Store) MirrorLedger(entries []Entry) {
	if s == nil || len(entries) == 0 {
		return
	}
	s.adoptChain(entries)
	chain := s.Chain()
	models := make([]mongo.WriteModel, 0, len(entries))
	for _, e := range entries {
		models = append(models, mongo.NewUpdateOneModel().
			SetFilter(bson.M{"_id": e.Hash}).
			SetUpsert(true).
			SetUpdate(bson.M{"$setOnInsert": bson.M{
				"chain": chain, "index": e.Index, "time": e.Time, "event": e.Event,
				"detail": e.Detail, "prev": e.Prev, "replicatedAt": time.Now().UTC(),
			}}))
	}
	s.enqueue("mirror ledger", func(ctx context.Context) error {
		ledger, _, _, _, _ := s.live()
		_, err := ledger.BulkWrite(ctx, models, options.BulkWrite().SetOrdered(true))
		return err
	})
}

// RecordDecisions stores one document per verified-or-refused payment, with the
// evidence that decided it, so the history is queryable per host and per check.
func (s *Store) RecordDecisions(runID string, scenarios []Scenario) {
	if s == nil || len(scenarios) == 0 {
		return
	}
	now := time.Now().UTC()
	docs := make([]any, 0, len(scenarios))
	for _, sc := range scenarios {
		ev := sc.Evidence
		doc := bson.M{
			"chain": s.Chain(), "runId": runID, "time": now, "scenario": sc.ID, "title": sc.Title,
			"expect": sc.Expect, "ok": ev.OK, "paid": sc.Paid, "amountUSD": sc.Amount,
			"fqdn": ev.FQDN, "reason": ev.Reason,
			"checks": bson.M{
				"identity": ev.Identity, "liveness": ev.Liveness, "authorization": ev.Authorization,
				"possession": ev.Possession, "quote": ev.Quote, "payee": ev.Payee,
			},
		}
		if a := ev.ANS; a != nil {
			doc["ans"] = ansDoc(a)
		}
		if sc.Payment != nil {
			doc["payment"] = bson.M{"rail": sc.Payment.Rail, "tx": sc.Payment.TxID,
				"withdrawal": sc.Payment.Withdrawal, "deposit": sc.Payment.Deposit, "payTo": sc.Payment.PayTo}
		}
		docs = append(docs, doc)
	}
	s.enqueue("record decisions", func(ctx context.Context) error {
		_, decisions, _, _, _ := s.live()
		_, err := decisions.InsertMany(ctx, docs)
		return err
	})
}

func ansDoc(a *ANSEvidence) bson.M {
	d := bson.M{
		"agentId": a.AgentID, "ansName": a.ANSName, "status": a.Status,
		"sealedFingerprint": a.SealedFingerprint, "leafIndex": a.LeafIndex,
		"treeSize": a.TreeSize, "displayName": a.DisplayName,
	}
	if a.TrustScore != nil {
		d["trustScore"] = *a.TrustScore
	}
	return d
}

// ObserveAgent keeps what ANS last said about a host, and the last 20
// observations, so a changed certificate, status or Trust Index shows up as
// drift rather than being silently overwritten.
func (s *Store) ObserveAgent(host string, a *ANSEvidence) {
	if s == nil || host == "" || a == nil {
		return
	}
	now := time.Now().UTC()
	obs := ansDoc(a)
	obs["time"] = now
	set := bson.M{"ansName": a.ANSName, "status": a.Status, "lastSeen": now, "latest": obs}
	s.enqueue("observe "+host, func(ctx context.Context) error {
		_, _, agents, _, _ := s.live()
		_, err := agents.UpdateOne(ctx, bson.M{"_id": host}, bson.M{
			"$set":         set,
			"$setOnInsert": bson.M{"firstSeen": now},
			"$inc":         bson.M{"observations": 1},
			"$push":        bson.M{"history": bson.M{"$each": []any{obs}, "$slice": -20}},
		}, options.UpdateOne().SetUpsert(true))
		return err
	})
}

// RecordAnchor stores a Solana anchor next to the entries it covers, so the
// on-chain proof and the replicated chain can be checked against each other.
func (s *Store) RecordAnchor(a Anchor) {
	if s == nil {
		return
	}
	s.enqueue("record anchor", func(ctx context.Context) error {
		_, _, _, anchors, _ := s.live()
		_, err := anchors.UpdateOne(ctx, bson.M{"_id": a.Signature + ":" + a.Head}, bson.M{
			"$set": bson.M{"chain": s.Chain(), "entries": a.Entries, "head": a.Head, "memo": a.Memo,
				"signature": a.Signature, "explorer": a.Explorer, "status": a.Status,
				"time": a.Time, "cluster": "devnet", "error": a.Error},
		}, options.UpdateOne().SetUpsert(true))
		return err
	})
}

// VerifyReplica re-reads the chain out of Atlas and recomputes every seal and
// link. It proves the replica is intact without trusting this process or the
// local file.
func (s *Store) VerifyReplica(ctx context.Context) (count int, ok bool, err error) {
	ledger, _, _, _, ok := s.live()
	if s == nil || !ok {
		return 0, false, errors.New("no MongoDB Atlas connection")
	}
	cur, err := ledger.Find(ctx, bson.M{"chain": s.Chain()}, options.Find().SetSort(bson.D{{Key: "index", Value: 1}}))
	if err != nil {
		return 0, false, errors.New(safeMongoErr(err))
	}
	defer cur.Close(ctx)
	prev := ""
	ok = true
	for cur.Next(ctx) {
		var d struct {
			Hash   string `bson:"_id"`
			Index  int    `bson:"index"`
			Time   string `bson:"time"`
			Event  string `bson:"event"`
			Detail string `bson:"detail"`
			Prev   string `bson:"prev"`
		}
		if err := cur.Decode(&d); err != nil {
			return count, false, errors.New(safeMongoErr(err))
		}
		e := Entry{Index: d.Index, Time: d.Time, Event: d.Event, Detail: d.Detail, Prev: d.Prev, Hash: d.Hash}
		if e.Index != count || e.Prev != prev || e.seal() != e.Hash {
			ok = false
		}
		prev = e.Hash
		count++
	}
	if err := cur.Err(); err != nil {
		return count, false, errors.New(safeMongoErr(err))
	}
	return count, ok, nil
}

// AtlasState is what the dashboard and /api/ledger report about the replica.
type AtlasState struct {
	Cluster   string `json:"cluster"`
	Database  string `json:"database"`
	Chain     string `json:"chain"`
	State     string `json:"state"`
	Entries   int    `json:"entries"`
	Intact    bool   `json:"intact"`
	Decisions int64  `json:"decisions"`
	Agents    int64  `json:"agents"`
	Anchors   int64  `json:"anchors"`
	Writes    int    `json:"writes"`
	Dropped   int    `json:"dropped,omitempty"`
	LastError string `json:"lastError,omitempty"`
}

func (s *Store) State(ctx context.Context) *AtlasState {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	st := &AtlasState{Database: mongoDatabase, Cluster: mongoHost(mongoURI()), Chain: s.chain,
		State: s.state, Writes: s.writes, Dropped: s.dropped, LastError: s.lastErr}
	s.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	n, ok, err := s.VerifyReplica(ctx)
	if err != nil {
		st.State = "unreachable: " + err.Error()
		return st
	}
	st.Entries, st.Intact = n, ok
	_, decisions, agents, anchors, _ := s.live()
	st.Decisions, _ = decisions.CountDocuments(ctx, bson.M{"chain": s.Chain()})
	st.Agents, _ = agents.CountDocuments(ctx, bson.M{})
	st.Anchors, _ = anchors.CountDocuments(ctx, bson.M{"chain": s.Chain()})
	return st
}

// Refusals answers, straight out of Atlas, the question the local file cannot:
// which check refused which host, how often, and when it last happened. An
// empty host covers every agent AgentVouch has decided about.
func (s *Store) Refusals(ctx context.Context, host string, limit int) ([]bson.M, error) {
	_, decisions, _, _, live := s.live()
	if s == nil || !live {
		return nil, errors.New("no MongoDB Atlas connection")
	}
	match := bson.M{"chain": s.Chain(), "ok": false}
	if host != "" {
		match["fqdn"] = strings.ToLower(host)
	}
	cur, err := decisions.Aggregate(ctx, []bson.M{
		{"$match": match},
		{"$group": bson.M{
			"_id":      bson.M{"fqdn": "$fqdn", "reason": "$reason"},
			"count":    bson.M{"$sum": 1},
			"lastSeen": bson.M{"$max": "$time"},
		}},
		{"$sort": bson.M{"count": -1, "lastSeen": -1}},
		{"$limit": limit},
		{"$project": bson.M{"_id": 0, "fqdn": "$_id.fqdn", "reason": "$_id.reason", "count": 1, "lastSeen": 1}},
	})
	if err != nil {
		return nil, errors.New(safeMongoErr(err))
	}
	defer cur.Close(ctx)
	var out []bson.M
	if err := cur.All(ctx, &out); err != nil {
		return nil, errors.New(safeMongoErr(err))
	}
	return out, nil
}

// HostReport is everything Atlas remembers about one hostname: what ANS said
// each time it was resolved, and every refusal it has collected. It is how
// AgentVouch answers "has this agent changed?" - drift in a certificate, a
// status or a Trust Index shows as history, not as a silent overwrite.
func (s *Store) HostReport(ctx context.Context, host string) (map[string]any, error) {
	_, _, agents, _, live := s.live()
	if s == nil || !live {
		return nil, errors.New("no MongoDB Atlas connection")
	}
	host = strings.ToLower(strings.TrimSpace(host))
	out := map[string]any{"host": host, "source": "MongoDB Atlas"}
	var doc bson.M
	err := agents.FindOne(ctx, bson.M{"_id": host}).Decode(&doc)
	switch {
	case errors.Is(err, mongo.ErrNoDocuments):
		out["note"] = "AgentVouch has never resolved this hostname"
	case err != nil:
		return nil, errors.New(safeMongoErr(err))
	default:
		out["firstSeen"], out["lastSeen"] = doc["firstSeen"], doc["lastSeen"]
		out["observations"], out["latest"] = doc["observations"], doc["latest"]
		out["history"] = doc["history"]
	}
	refusals, err := s.Refusals(ctx, host, 10)
	if err != nil {
		return nil, err
	}
	out["refusals"] = refusals
	return out, nil
}

// mongoCheck is the `go run . mongo-check` command: prove the connection, the
// replica and its integrity from the command line.
func mongoCheck(ctx context.Context) error {
	store := newStore()
	if store == nil {
		return errors.New("set MONGODB_URI first")
	}
	if err := store.connect(ctx); err != nil {
		return err
	}
	defer store.client.Disconnect(context.Background())
	st := store.State(ctx)
	log.Printf("cluster %s  database %s  %s", st.Cluster, st.Database, st.State)
	log.Printf("chain %s: %d entries replicated, intact: %v", short(st.Chain, 12), st.Entries, st.Intact)
	log.Printf("decisions: %d  agents: %d  anchors: %d", st.Decisions, st.Agents, st.Anchors)
	top, err := store.Refusals(ctx, "", 5)
	if err != nil {
		return err
	}
	for _, r := range top {
		log.Printf("refused %v x%v: %.90v", r["fqdn"], r["count"], r["reason"])
	}
	return nil
}
