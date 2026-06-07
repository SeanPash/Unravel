package graph

import (
	"context"
	"testing"
	"time"

	"github.com/luigifernandez/unravel/engine/internal/types"
)

func TestPersister_SaveAndLoadRoundtrip(t *testing.T) {
	g := New()
	parent := g.FindOrCreateNode(types.NodeKindProcess, "WS01-100", "cmd.exe", map[string]any{"pid": 100})
	child := g.FindOrCreateNode(types.NodeKindProcess, "WS01-200", "powershell.exe", map[string]any{"pid": 200})
	ts := time.Date(2026, 6, 5, 19, 30, 0, 0, time.UTC)
	g.AppendEdge(parent, child, types.EdgeKindSpawned, ts, 0.8, "evt-001")

	dir := t.TempDir()
	p, err := OpenPersister(dir)
	if err != nil {
		t.Fatalf("OpenPersister: %v", err)
	}
	defer p.Close()

	if err := p.Save(g.Snapshot()); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := p.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(loaded.Nodes) != 2 {
		t.Errorf("loaded Nodes len = %d, want 2", len(loaded.Nodes))
	}
	if len(loaded.Edges) != 1 {
		t.Errorf("loaded Edges len = %d, want 1", len(loaded.Edges))
	}
	if loaded.Edges[0].SourceEventID != "evt-001" {
		t.Errorf("loaded edge SourceEventID = %q, want evt-001", loaded.Edges[0].SourceEventID)
	}
}

func TestPersister_LoadEmptyReturnsEmptySnapshot(t *testing.T) {
	dir := t.TempDir()
	p, err := OpenPersister(dir)
	if err != nil {
		t.Fatalf("OpenPersister: %v", err)
	}
	defer p.Close()

	loaded, err := p.Load()
	if err != nil {
		t.Fatalf("Load on empty store: %v", err)
	}
	if len(loaded.Nodes) != 0 || len(loaded.Edges) != 0 {
		t.Errorf("Load on empty store = %+v, want empty", loaded)
	}
}

func TestPersister_SaveOverwritesPriorSnapshot(t *testing.T) {
	dir := t.TempDir()
	p, err := OpenPersister(dir)
	if err != nil {
		t.Fatalf("OpenPersister: %v", err)
	}
	defer p.Close()

	g1 := New()
	g1.FindOrCreateNode(types.NodeKindProcess, "a", "a", nil)
	if err := p.Save(g1.Snapshot()); err != nil {
		t.Fatalf("Save 1: %v", err)
	}

	g2 := New()
	g2.FindOrCreateNode(types.NodeKindProcess, "x", "x", nil)
	g2.FindOrCreateNode(types.NodeKindProcess, "y", "y", nil)
	if err := p.Save(g2.Snapshot()); err != nil {
		t.Fatalf("Save 2: %v", err)
	}

	loaded, err := p.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(loaded.Nodes) != 2 {
		t.Errorf("after overwrite loaded.Nodes len = %d, want 2", len(loaded.Nodes))
	}
	ids := map[string]bool{}
	for _, n := range loaded.Nodes {
		ids[n.ID] = true
	}
	if ids[NodeID(types.NodeKindProcess, "a")] {
		t.Errorf("prior-snapshot node leaked into latest load: %+v", loaded.Nodes)
	}
}

func TestPersister_RunWritesSnapshotsPeriodically(t *testing.T) {
	dir := t.TempDir()
	p, err := OpenPersister(dir)
	if err != nil {
		t.Fatalf("OpenPersister: %v", err)
	}
	defer p.Close()

	g := New()
	g.FindOrCreateNode(types.NodeKindHost, "WS01", "WS01", nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	saved := make(chan struct{}, 8)
	p.onSaved = func() { saved <- struct{}{} }

	done := make(chan struct{})
	go func() {
		p.Run(ctx, g, 5*time.Millisecond)
		close(done)
	}()

	select {
	case <-saved:
	case <-time.After(time.Second):
		t.Fatal("Run did not produce a snapshot within 1s")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not return after context cancel")
	}

	loaded, err := p.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(loaded.Nodes) != 1 || loaded.Nodes[0].ID != NodeID(types.NodeKindHost, "WS01") {
		t.Errorf("Load after Run = %+v, want one host WS01", loaded)
	}
}
