package protocol

import "testing"

func TestBeginSignTask_perKeyID_parallel(t *testing.T) {
	node := "node0"
	keyA := "key-a"
	keyB := "key-b"

	if !beginSignTask("task-a1", node, keyA) {
		t.Fatal("begin task-a1")
	}
	if !beginSignTask("task-b1", node, keyB) {
		t.Fatal("different keyID should run in parallel on same node")
	}
	if beginSignTask("task-a2", node, keyA) {
		t.Fatal("same keyID should be exclusive on same node")
	}
	if beginSignTask("task-a1", node, keyA) {
		t.Fatal("duplicate same taskID should be rejected")
	}

	endSignTask("task-a1", node)
	if !beginSignTask("task-a2", node, keyA) {
		t.Fatal("should allow new task after previous key task ends")
	}

	endSignTask("task-b1", node)
	endSignTask("task-a2", node)

	if activeSignTaskForKey(node, keyA) != "" || activeSignTaskForKey(node, keyB) != "" {
		t.Fatal("active map should be empty after end")
	}
}

func TestActiveSignTaskForKey_tracksBusyTask(t *testing.T) {
	node := "node1"
	key := "key-x"
	if activeSignTaskForKey(node, key) != "" {
		t.Fatal("expected empty")
	}
	if !beginSignTask("task-x", node, key) {
		t.Fatal("begin")
	}
	if got := activeSignTaskForKey(node, key); got != "task-x" {
		t.Fatalf("want task-x got %q", got)
	}
	endSignTask("task-x", node)
}
