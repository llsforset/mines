package litebeacon

import (
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
	s.PushResults("abc", []ExecResult{{TaskID: 1, Exit: 0, Output: []byte("hi")}}, nil, now)
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
		s.PushResults("abc", []ExecResult{{TaskID: uint32(i + 1), Exit: 0, Output: big}}, nil, now)
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
