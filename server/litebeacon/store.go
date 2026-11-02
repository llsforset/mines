package litebeacon

import (
	"sort"
	"sync"
	"time"

	"github.com/bishopfox/sliver/server/log"
)

var storeLog = log.NamedLogger("litebeacon", "store")

const (
	maxQueuedTasks  = 32
	maxResults      = 32
	maxResultBytes  = 1 << 20
	maxRecentNonces = 64
)

// Beacon is the console-facing view of a known implant.
type Beacon struct {
	ID        string     `json:"ID"`
	Info      BeaconInfo `json:"Info"`
	SecretB64 string     `json:"SecretB64"`
	FirstSeen time.Time  `json:"FirstSeen"`
	LastSeen  time.Time  `json:"LastSeen"`
}

// Result is a completed task outcome, consumed by the console on read.
type Result struct {
	BeaconID string    `json:"BeaconID"`
	Kind     string    `json:"Kind"` // "exec" or "read"
	TaskID   uint32    `json:"TaskID"`
	Exit     int32     `json:"Exit"`
	Err      uint8     `json:"Err"`
	Output   []byte    `json:"Output"`
	At       time.Time `json:"At"`
}

type beaconState struct {
	info        BeaconInfo
	secretB64   string
	firstSeen   time.Time
	lastSeen    time.Time
	tasks       []Task
	results     []Result
	resultBytes int
	nonces      map[string]struct{}
	nonceOrder  []string
}

// Store holds all lite beacon state in memory.
type Store struct {
	mutex   sync.Mutex
	beacons map[string]*beaconState
	taskSeq uint32
}

func NewStore() *Store {
	return &Store{beacons: map[string]*beaconState{}}
}

// Touch upserts the beacon, refreshes last-seen and enforces the replay
// window. It returns true when the nonce was already seen (reject the call).
func (s *Store) Touch(id string, nonce []byte, info *BeaconInfo, secretB64 string, now time.Time) (replayed bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	st, ok := s.beacons[id]
	if !ok {
		st = &beaconState{nonces: map[string]struct{}{}}
		st.firstSeen = now
		st.info.ID = id
		s.beacons[id] = st
	}
	nonceKey := string(nonce)
	if _, dup := st.nonces[nonceKey]; dup {
		return true
	}
	st.nonces[nonceKey] = struct{}{}
	st.nonceOrder = append(st.nonceOrder, nonceKey)
	if len(st.nonceOrder) > maxRecentNonces {
		delete(st.nonces, st.nonceOrder[0])
		st.nonceOrder = st.nonceOrder[1:]
	}
	if info != nil {
		merged := *info
		merged.ID = id
		st.info = merged
	}
	st.secretB64 = secretB64
	st.lastSeen = now
	return false
}

// QueueTask assigns the task an ID and queues it for the next check-in.
// It fails (ok=false) when the beacon is unknown.
func (s *Store) QueueTask(id string, t Task) (Task, bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	st, ok := s.beacons[id]
	if !ok {
		return t, false
	}
	s.taskSeq++
	t.ID = s.taskSeq
	st.tasks = append(st.tasks, t)
	if len(st.tasks) > maxQueuedTasks {
		dropped := st.tasks[0]
		st.tasks = st.tasks[len(st.tasks)-maxQueuedTasks:]
		storeLog.Warnf("beacon %s task queue full: dropped oldest task %d (%#x)", id, dropped.ID, dropped.Type)
	}
	return t, true
}

func (s *Store) TakeTasks(id string) []Task {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	st, ok := s.beacons[id]
	if !ok {
		return nil
	}
	tasks := st.tasks
	st.tasks = nil
	return tasks
}

func (s *Store) Delete(id string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	delete(s.beacons, id)
}

func (s *Store) PushResults(id string, execs []ExecResult, files []FileResult, now time.Time) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	st, ok := s.beacons[id]
	if !ok {
		return
	}
	push := func(r Result) {
		st.results = append(st.results, r)
		st.resultBytes += len(r.Output)
		for len(st.results) > 0 && (len(st.results) > maxResults || st.resultBytes > maxResultBytes) {
			st.resultBytes -= len(st.results[0].Output)
			st.results = st.results[1:]
		}
	}
	for _, e := range execs {
		push(Result{BeaconID: id, Kind: "exec", TaskID: e.TaskID, Exit: e.Exit, Output: e.Output, At: now})
	}
	for _, f := range files {
		push(Result{BeaconID: id, Kind: "read", TaskID: f.TaskID, Err: f.Err, Output: f.Content, At: now})
	}
}

func (s *Store) TakeResults(id string) []Result {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	st, ok := s.beacons[id]
	if !ok {
		return nil
	}
	results := st.results
	st.results = nil
	st.resultBytes = 0
	return results
}

func (s *Store) ListBeacons() []Beacon {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	out := make([]Beacon, 0, len(s.beacons))
	for id, st := range s.beacons {
		out = append(out, Beacon{ID: id, Info: st.info, SecretB64: st.secretB64, FirstSeen: st.firstSeen, LastSeen: st.lastSeen})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out
}
