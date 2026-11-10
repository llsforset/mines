package litebeacon

import (
	"bytes"
	"testing"
	"time"
)

func TestTouchUpsertsAndDetectsReplay(t *testing.T) {
	s := NewStore()
	now := time.Now()
	info := &BeaconInfo{Hostname: "web01", OS: "Linux", Arch: "amd64", Username: "root", PID: 1}
	if s.Touch("abc", []byte("nonce-1"), info, "aa", now) {
		t.Fatal("first touch must not be a replay")
	}
	if !s.Touch("abc", []byte("nonce-1"), nil, "aa", now) {
		t.Fatal("same nonce must be flagged as replay")
	}
	if s.Touch("abc", []byte("nonce-2"), nil, "aa", now) {
		t.Fatal("fresh nonce must not be a replay")
	}
	beacons := s.ListBeacons()
	if len(beacons) != 1 || beacons[0].ID != "abc" || beacons[0].Info.Hostname != "web01" {
		t.Fatalf("bad beacons: %#v", beacons)
	}
	if !beacons[0].FirstSeen.Equal(now) {
		t.Fatalf("first seen not recorded: %v", beacons[0].FirstSeen)
	}
}

func TestQueueTakeTasks(t *testing.T) {
	s := NewStore()
	now := time.Now()
	s.Touch("abc", []byte("n1"), &BeaconInfo{Hostname: "h"}, "", now)
	if _, ok := s.QueueTask("missing", Task{Type: TaskExit}); ok {
		t.Fatal("queueing to unknown beacon must fail")
	}
	queued, ok := s.QueueTask("abc", Task{Type: TaskExec, Cmd: "id"})
	if !ok || queued.ID != 1 {
		t.Fatalf("queue result: %#v ok=%v", queued, ok)
	}
	tasks := s.TakeTasks("abc")
	if len(tasks) != 1 || tasks[0].ID != 1 {
		t.Fatalf("take: %#v", tasks)
	}
	if again := s.TakeTasks("abc"); len(again) != 0 {
		t.Fatalf("tasks must drain: %#v", again)
	}
}

func TestQueueTaskCapDropsOldest(t *testing.T) {
	s := NewStore()
	s.Touch("abc", []byte("n1"), &BeaconInfo{Hostname: "h"}, "", time.Now())
	for i := 0; i < maxQueuedTasks+5; i++ {
		s.QueueTask("abc", Task{Type: TaskExec, Cmd: "x"})
	}
	tasks := s.TakeTasks("abc")
	if len(tasks) != maxQueuedTasks {
		t.Fatalf("kept %d tasks, want %d", len(tasks), maxQueuedTasks)
	}
}

func TestPushTakeResults(t *testing.T) {
	s := NewStore()
	now := time.Now()
	s.Touch("abc", []byte("n1"), &BeaconInfo{Hostname: "h"}, "", now)
	s.PushResults("abc", []ExecResult{{TaskID: 1, Exit: 0, Output: []byte("hi")}}, nil, nil, nil, now)
	results := s.TakeResults("abc")
	if len(results) != 1 || results[0].Kind != "exec" || string(results[0].Output) != "hi" {
		t.Fatalf("results: %#v", results)
	}
	if again := s.TakeResults("abc"); len(again) != 0 {
		t.Fatalf("results must drain: %#v", again)
	}
}

func TestResultByteCapEvictsOldest(t *testing.T) {
	s := NewStore()
	now := time.Now()
	s.Touch("abc", []byte("n1"), nil, "", now)
	big := make([]byte, maxResultBytes/3)
	for i := 0; i < 5; i++ {
		s.PushResults("abc", []ExecResult{{TaskID: uint32(i + 1), Exit: 0, Output: big}}, nil, nil, nil, now)
	}
	results := s.TakeResults("abc")
	if len(results) != 3 {
		t.Fatalf("expected 3 kept results, got %d", len(results))
	}
	if results[0].TaskID != 3 {
		t.Fatalf("oldest evicted, first kept = %#v", results[0])
	}
}

func TestDeleteBeacon(t *testing.T) {
	s := NewStore()
	s.Touch("abc", []byte("n1"), nil, "", time.Now())
	s.Delete("abc")
	if beacons := s.ListBeacons(); len(beacons) != 0 {
		t.Fatalf("delete failed: %#v", beacons)
	}
}

func TestIntervalPolicy(t *testing.T) {
	s := NewStore()
	if idle, fast := s.IntervalPolicy(); idle != 10 || fast != 10 {
		t.Fatalf("defaults: idle=%d fast=%d", idle, fast)
	}
	s.SetIntervalPolicy(60, 10)
	if idle, fast := s.IntervalPolicy(); idle != 60 || fast != 10 {
		t.Fatalf("policy set: idle=%d fast=%d", idle, fast)
	}
	// clamp 边界
	s.SetIntervalPolicy(1, 100000)
	if idle, fast := s.IntervalPolicy(); idle != 5 || fast != 86400 {
		t.Fatalf("clamp: idle=%d fast=%d", idle, fast)
	}
	s.SetIntervalPolicy(60, 10)

	now := time.Now()
	s.nowFn = func() time.Time { return now }
	s.Touch("abc", []byte("n1"), nil, "", now)
	if got := s.NextInterval("abc"); got != 60 {
		t.Fatalf("idle beacon should use policy idle value, got %d", got)
	}
	// sleep 任务落地基准值后，空闲用基准
	s.SetBaseInterval("abc", 180)
	if got := s.NextInterval("abc"); got != 180 {
		t.Fatalf("base override not honored, got %d", got)
	}
	// 排任务 → 活跃 → 快间隔
	s.QueueTask("abc", Task{Type: TaskExec, Cmd: "id"})
	if got := s.NextInterval("abc"); got != 10 {
		t.Fatalf("active window should use fast value, got %d", got)
	}
	if sec, exact := s.IntervalHint("abc"); sec != 10 || !exact {
		t.Fatalf("active window should be an exact sleep, sec=%d exact=%v", sec, exact)
	}
	// 页面轮询拉结果不算干活，不能把活跃窗口续上
	s.PushResults("abc", []ExecResult{{TaskID: 1, Output: []byte("x")}}, nil, nil, nil, now)
	s.TakeResults("abc")
	now = now.Add(6 * time.Minute)
	if got := s.NextInterval("abc"); got != 180 {
		t.Fatalf("result polling must not extend the active window, got %d", got)
	}
	if sec, exact := s.IntervalHint("abc"); sec != 180 || exact {
		t.Fatalf("idle hint should jitter, sec=%d exact=%v", sec, exact)
	}
	// 未见过的新信标 → 策略空闲值
	if got := s.NextInterval("unknown"); got != 60 {
		t.Fatalf("unknown beacon should use idle policy, got %d", got)
	}
}

func TestListBeaconsHeartbeat(t *testing.T) {
	s := NewStore()
	s.SetIntervalPolicy(60, 10)
	now := time.Now()
	s.nowFn = func() time.Time { return now }
	s.Touch("abc", []byte("n1"), &BeaconInfo{Hostname: "web01", Username: "root"}, "", now)

	got := s.ListBeacons()
	if len(got) != 1 {
		t.Fatalf("want 1 beacon, got %#v", got)
	}
	b := got[0]
	if b.IntervalSec != 60 || b.IdleSec != 60 || b.FastSec != 10 || b.Active || b.Queued != 0 {
		t.Fatalf("idle list fields: %#v", b)
	}

	s.QueueTask("abc", Task{Type: TaskExec, Cmd: "id"})
	b = s.ListBeacons()[0]
	if !b.Active || b.IntervalSec != 10 || b.Queued != 1 {
		t.Fatalf("active list fields: %#v", b)
	}
}

func TestFileChunkReassembly(t *testing.T) {
	s := NewStore()
	now := time.Now()
	s.Touch("abc", []byte("n1"), nil, "", now)
	queued, ok := s.QueueTask("abc", Task{Type: TaskRead, Path: "/tmp/blob"})
	if !ok {
		t.Fatal("queue read")
	}
	tasks := s.TakeTasks("abc")
	if len(tasks) != 1 || tasks[0].Offset != 0 {
		t.Fatalf("first task: %#v", tasks)
	}

	first := bytes.Repeat([]byte("A"), fileChunkSize)
	rest := []byte("tail-bytes")
	total := uint32(len(first) + len(rest))
	s.PushResults("abc", nil, []FileResult{{
		TaskID: queued.ID, Chunked: true, Offset: 0, Total: total, Content: first,
	}}, nil, nil, now)
	if got := s.TakeResults("abc"); len(got) != 0 {
		t.Fatalf("partial file should not complete: %#v", got)
	}
	cont := s.TakeTasks("abc")
	if len(cont) != 1 || cont[0].ID != queued.ID || cont[0].Offset != uint32(len(first)) || cont[0].Path != "/tmp/blob" {
		t.Fatalf("continuation: %#v", cont)
	}

	s.PushResults("abc", nil, []FileResult{{
		TaskID: queued.ID, Chunked: true, Offset: uint32(len(first)), Total: total, Content: rest,
	}}, nil, nil, now)
	results := s.TakeResults("abc")
	if len(results) != 1 || results[0].Err != 0 || results[0].Path != "/tmp/blob" {
		t.Fatalf("complete: %#v", results)
	}
	want := append(append([]byte{}, first...), rest...)
	if !bytes.Equal(results[0].Output, want) {
		t.Fatalf("reassembled %d bytes, want %d", len(results[0].Output), len(want))
	}
}

func TestFileTransferRestartOnMismatch(t *testing.T) {
	s := NewStore()
	now := time.Now()
	s.Touch("abc", []byte("n1"), nil, "", now)
	queued, ok := s.QueueTask("abc", Task{Type: TaskRead, Path: "/tmp/blob"})
	if !ok {
		t.Fatal("queue read")
	}
	_ = s.TakeTasks("abc")
	s.PushResults("abc", nil, []FileResult{{
		TaskID: queued.ID, Chunked: true, Offset: 0, Total: 100, Content: bytes.Repeat([]byte("A"), 50),
	}}, nil, nil, now)
	s.PushResults("abc", nil, []FileResult{{
		TaskID: queued.ID, Chunked: true, Offset: 50, Total: 90, Content: bytes.Repeat([]byte("B"), 40),
	}}, nil, nil, now)
	results := s.TakeResults("abc")
	if len(results) != 1 || results[0].Err != 4 {
		t.Fatalf("mismatch should abort: %#v", results)
	}
	if extra := s.TakeTasks("abc"); len(extra) != 0 {
		t.Fatalf("failed transfer must not continue: %#v", extra)
	}
}

func TestFileTransferRestartOnError(t *testing.T) {
	s := NewStore()
	now := time.Now()
	s.Touch("abc", []byte("n1"), nil, "", now)
	queued, ok := s.QueueTask("abc", Task{Type: TaskRead, Path: "/tmp/blob"})
	if !ok {
		t.Fatal("queue read")
	}
	_ = s.TakeTasks("abc")
	s.PushResults("abc", nil, []FileResult{{
		TaskID: queued.ID, Chunked: true, Offset: 0, Total: 100, Content: bytes.Repeat([]byte("A"), 50),
	}}, nil, nil, now)
	s.PushResults("abc", nil, []FileResult{{
		TaskID: queued.ID, Err: 1, Chunked: true,
	}}, nil, nil, now)
	results := s.TakeResults("abc")
	if len(results) != 1 || results[0].Err != 1 || results[0].Path != "/tmp/blob" {
		t.Fatalf("error should abort: %#v", results)
	}
	if extra := s.TakeTasks("abc"); len(extra) != 0 {
		t.Fatalf("failed transfer must not continue: %#v", extra)
	}
}

func TestFileJobCap(t *testing.T) {
	s := NewStore()
	s.Touch("abc", []byte("n1"), nil, "", time.Now())
	for i := 0; i < maxFileJobs; i++ {
		if _, ok := s.QueueTask("abc", Task{Type: TaskRead, Path: "/tmp/a"}); !ok {
			t.Fatalf("read %d should queue", i)
		}
	}
	if _, ok := s.QueueTask("abc", Task{Type: TaskRead, Path: "/tmp/b"}); ok {
		t.Fatal("fifth read should be refused")
	}
	if _, ok := s.QueueTask("abc", Task{Type: TaskExec, Cmd: "id"}); !ok {
		t.Fatal("exec should still queue")
	}
}

func TestCompletedFileNotEvictedByExecCap(t *testing.T) {
	s := NewStore()
	now := time.Now()
	s.Touch("abc", []byte("n1"), nil, "", now)
	queued, ok := s.QueueTask("abc", Task{Type: TaskRead, Path: "/tmp/blob"})
	if !ok {
		t.Fatal("queue read")
	}
	_ = s.TakeTasks("abc")
	body := bytes.Repeat([]byte("Z"), 2<<20)
	s.PushResults("abc", nil, []FileResult{{
		TaskID: queued.ID, Chunked: true, Offset: 0, Total: uint32(len(body)), Content: body,
	}}, nil, nil, now)
	big := make([]byte, maxResultBytes/3)
	for i := 0; i < 5; i++ {
		s.PushResults("abc", []ExecResult{{TaskID: uint32(i + 10), Output: big}}, nil, nil, nil, now)
	}
	results := s.TakeResults("abc")
	if len(results) == 0 || results[0].Kind != "read" || len(results[0].Output) != len(body) {
		t.Fatalf("file result was evicted: %#v", results)
	}
}

func TestEmptyFileCompletes(t *testing.T) {
	s := NewStore()
	now := time.Now()
	s.Touch("abc", []byte("n1"), nil, "", now)
	queued, ok := s.QueueTask("abc", Task{Type: TaskRead, Path: "/tmp/empty"})
	if !ok {
		t.Fatal("queue read")
	}
	_ = s.TakeTasks("abc")
	s.PushResults("abc", nil, []FileResult{{
		TaskID: queued.ID, Chunked: true, Offset: 0, Total: 0,
	}}, nil, nil, now)
	results := s.TakeResults("abc")
	if len(results) != 1 || results[0].Err != 0 || len(results[0].Output) != 0 {
		t.Fatalf("empty file: %#v", results)
	}
}

func TestDirListRequestAndCache(t *testing.T) {
	s := NewStore()
	now := time.Now()
	s.nowFn = func() time.Time { return now }
	s.Touch("abc", []byte("n1"), nil, "", now)

	queued, pending := s.RequestDir("abc", "/etc", false)
	if !queued || pending {
		t.Fatalf("first request should queue: queued=%v pending=%v", queued, pending)
	}
	tasks := s.TakeTasks("abc")
	if len(tasks) != 1 || tasks[0].Type != TaskListDir || tasks[0].Path != "/etc" {
		t.Fatalf("listdir task: %#v", tasks)
	}

	// 请求在途：同路径不重复入队
	queued, pending = s.RequestDir("abc", "/etc", false)
	if queued || !pending {
		t.Fatalf("in-flight request should dedupe: queued=%v pending=%v", queued, pending)
	}

	// 结果回来 → 缓存里能查到，pending 清空
	s.PushResults("abc", nil, nil, []DirResult{{
		TaskID:  tasks[0].ID,
		Err:     0,
		Entries: []DirEntry{{Name: "hosts", Size: 128, ModTime: 1700000000}},
	}}, nil, now)
	listing, found, pend := s.DirStatus("abc", "/etc")
	if !found || pend || listing.Err != 0 || len(listing.Entries) != 1 || listing.Entries[0].Name != "hosts" {
		t.Fatalf("cached listing: %#v found=%v pend=%v", listing, found, pend)
	}

	// 缓存新鲜（60s 内）且不强制 → 不再入队
	queued, pending = s.RequestDir("abc", "/etc", false)
	if queued || pending {
		t.Fatalf("fresh cache should serve: queued=%v pending=%v", queued, pending)
	}
	// 强制刷新 → 重新入队
	queued, pending = s.RequestDir("abc", "/etc", true)
	if !queued || pending {
		t.Fatalf("force should requeue: queued=%v pending=%v", queued, pending)
	}
	tasks = s.TakeTasks("abc")
	if len(tasks) != 1 || tasks[0].Type != TaskListDir {
		t.Fatalf("force task: %#v", tasks)
	}

	// 缓存过期后重新请求
	now = now.Add(2 * time.Minute)
	queued, pending = s.RequestDir("abc", "/etc", false)
	if !queued {
		t.Fatal("stale cache should requeue")
	}

	// 错误结果也会落缓存，前端能显示原因
	tasks = s.TakeTasks("abc")
	s.PushResults("abc", nil, nil, []DirResult{{TaskID: tasks[0].ID, Err: 2}}, nil, now)
	listing, found, _ = s.DirStatus("abc", "/etc")
	if !found || listing.Err != 2 {
		t.Fatalf("error listing: %#v", listing)
	}

	// 未知信标
	if queued, pending := s.RequestDir("missing", "/x", false); queued || pending {
		t.Fatal("unknown beacon must not queue")
	}
	if _, found, _ := s.DirStatus("missing", "/x"); found {
		t.Fatal("unknown beacon has no cache")
	}
}

func TestCompletedFileHook(t *testing.T) {
	s := NewStore()
	now := time.Now()
	s.Touch("abc", []byte("n1"), nil, "", now)
	queued, ok := s.QueueTask("abc", Task{Type: TaskRead, Path: "/tmp/x"})
	if !ok {
		t.Fatal("queue read")
	}
	_ = s.TakeTasks("abc")

	var got struct {
		beacon string
		taskID uint32
		path   string
		data   []byte
	}
	prev := OnCompletedFile
	OnCompletedFile = func(beaconID string, taskID uint32, path string, data []byte) {
		got = struct {
			beacon string
			taskID uint32
			path   string
			data   []byte
		}{beaconID, taskID, path, data}
	}
	defer func() { OnCompletedFile = prev }()

	s.PushResults("abc", nil, []FileResult{{
		TaskID: queued.ID, Chunked: true, Offset: 0, Total: 5, Content: []byte("hello"),
	}}, nil, nil, now)
	if got.beacon != "abc" || got.taskID != queued.ID || got.path != "/tmp/x" || string(got.data) != "hello" {
		t.Fatalf("hook: %#v", got)
	}

	// 失败不回调
	got = struct {
		beacon string
		taskID uint32
		path   string
		data   []byte
	}{}
	queued2, ok := s.QueueTask("abc", Task{Type: TaskRead, Path: "/tmp/y"})
	if !ok {
		t.Fatal("queue read 2")
	}
	_ = s.TakeTasks("abc")
	s.PushResults("abc", nil, []FileResult{{TaskID: queued2.ID, Err: 1, Chunked: true}}, nil, nil, now)
	if got.beacon != "" {
		t.Fatalf("failed read must not call the hook: %#v", got)
	}
}

func TestWriteJobChunkFlow(t *testing.T) {
	s := NewStore()
	now := time.Now()
	s.nowFn = func() time.Time { return now }
	s.Touch("abc", []byte("n1"), nil, "", now)

	body := bytes.Repeat([]byte("W"), fileChunkSize+10) // 需要 2 块
	queued, ok := s.QueueTask("abc", Task{
		Type: TaskWrite, Path: "/tmp/a.txt", Data: body, ExpectSize: -1, ExpectMTime: -1, Force: true,
	})
	if !ok {
		t.Fatal("queue write")
	}
	if queued.ID == 0 {
		t.Fatal("job id assigned")
	}
	// 第一块已经入队
	tasks := s.TakeTasks("abc")
	if len(tasks) != 1 || tasks[0].Type != TaskWrite || tasks[0].Offset != 0 {
		t.Fatalf("first chunk: %#v", tasks)
	}
	if !bytes.Equal(tasks[0].Data, body[:fileChunkSize]) {
		t.Fatal("first chunk payload")
	}
	if tasks[0].Total != uint64(len(body)) {
		t.Fatalf("total on wire: %d", tasks[0].Total)
	}

	// ACK 第一块 → 第二块自动入队
	s.PushResults("abc", nil, nil, nil, []StatusResult{{TaskID: tasks[0].ID, Err: 0}}, now)
	tasks = s.TakeTasks("abc")
	if len(tasks) != 1 || tasks[0].Offset != fileChunkSize {
		t.Fatalf("second chunk: %#v", tasks)
	}
	if !bytes.Equal(tasks[0].Data, body[fileChunkSize:]) {
		t.Fatal("second chunk payload")
	}

	// ACK 第二块 → 完成，fs 结果进队列
	s.PushResults("abc", nil, nil, nil, []StatusResult{{TaskID: tasks[0].ID, Err: 0}}, now)
	results := s.TakeResults("abc")
	if len(results) != 1 || results[0].Kind != "fs" || results[0].Op != "write" || results[0].Err != 0 || results[0].Path != "/tmp/a.txt" {
		t.Fatalf("write completion: %#v", results)
	}
	// 无残留任务
	if extra := s.TakeTasks("abc"); len(extra) != 0 {
		t.Fatalf("leftover tasks: %#v", extra)
	}
}

func TestWriteJobAbortsOnError(t *testing.T) {
	s := NewStore()
	now := time.Now()
	s.Touch("abc", []byte("n1"), nil, "", now)
	if _, ok := s.QueueTask("abc", Task{Type: TaskWrite, Path: "/tmp/a.txt", Data: []byte("hello"), Force: true}); !ok {
		t.Fatal("queue write")
	}
	tasks := s.TakeTasks("abc")
	// 写盘失败（如权限）→ abort，不再续块
	s.PushResults("abc", nil, nil, nil, []StatusResult{{TaskID: tasks[0].ID, Err: 2}}, now)
	results := s.TakeResults("abc")
	if len(results) != 1 || results[0].Kind != "fs" || results[0].Err != 2 {
		t.Fatalf("abort outcome: %#v", results)
	}
	if extra := s.TakeTasks("abc"); len(extra) != 0 {
		t.Fatalf("aborted write must not continue: %#v", extra)
	}
}

func TestWriteJobStaleSweep(t *testing.T) {
	s := NewStore()
	now := time.Now()
	s.nowFn = func() time.Time { return now }
	s.Touch("abc", []byte("n1"), nil, "", now)
	if _, ok := s.QueueTask("abc", Task{Type: TaskWrite, Path: "/tmp/a.txt", Data: []byte("hi"), Force: true}); !ok {
		t.Fatal("queue write")
	}
	_ = s.TakeTasks("abc")
	// 心跳一直在来，但植入体从不应答 → 超时作废
	now = now.Add(fsOpTTL + time.Minute)
	s.PushResults("abc", []ExecResult{{TaskID: 999, Output: []byte("x")}}, nil, nil, nil, now)
	results := s.TakeResults("abc")
	found := false
	for _, r := range results {
		if r.Kind == "fs" && r.Err == 8 {
			found = true
		}
	}
	if !found {
		t.Fatalf("stale write should abort: %#v", results)
	}
}

func TestFsSingleOps(t *testing.T) {
	s := NewStore()
	now := time.Now()
	s.Touch("abc", []byte("n1"), nil, "", now)
	for _, tc := range []struct {
		task Task
		op   string
	}{
		{Task{Type: TaskRm, Path: "/tmp/a", Recursive: true}, "rm"},
		{Task{Type: TaskMv, Path: "/tmp/a", Dst: "/tmp/b"}, "mv"},
		{Task{Type: TaskMkdir, Path: "/tmp/c"}, "mkdir"},
	} {
		if _, ok := s.QueueTask("abc", tc.task); !ok {
			t.Fatalf("%s queue", tc.op)
		}
		tasks := s.TakeTasks("abc")
		if len(tasks) != 1 {
			t.Fatalf("%s task: %#v", tc.op, tasks)
		}
		s.PushResults("abc", nil, nil, nil, []StatusResult{{TaskID: tasks[0].ID, Err: 0}}, now)
		results := s.TakeResults("abc")
		if len(results) != 1 || results[0].Kind != "fs" || results[0].Op != tc.op || results[0].Err != 0 {
			t.Fatalf("%s outcome: %#v", tc.op, results)
		}
	}
}

func TestTransferCapShared(t *testing.T) {
	s := NewStore()
	now := time.Now()
	s.Touch("abc", []byte("n1"), nil, "", now)
	for i := 0; i < maxFileJobs; i++ {
		if _, ok := s.QueueTask("abc", Task{Type: TaskRead, Path: "/tmp/a"}); !ok {
			t.Fatalf("read %d should queue", i)
		}
	}
	if _, ok := s.QueueTask("abc", Task{Type: TaskWrite, Path: "/tmp/b", Data: []byte("x"), Force: true}); ok {
		t.Fatal("write should be refused when cap reached")
	}
	if _, ok := s.QueueTask("abc", Task{Type: TaskExec, Cmd: "id"}); !ok {
		t.Fatal("exec still queues")
	}
}
