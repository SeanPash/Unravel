package graph

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/luigifernandez/unravel/engine/internal/types"
)

// snapshotKey is the single BadgerDB key under which the latest GraphUpdatePayload
// is stored. A new Save overwrites the previous value; we only need the most
// recent snapshot for crash recovery.
var snapshotKey = []byte("graph/snapshot/latest")

// Persister owns a BadgerDB handle and writes periodic Graph snapshots to it so
// the engine can recover its in-memory state after a crash. The store keeps a
// single rolling snapshot under snapshotKey.
type Persister struct {
	db *badger.DB
	// onSaved, if set, is invoked after each successful Save performed by Run.
	// Used by tests to deterministically wait for a snapshot to land without
	// polling the DB.
	onSaved func()
}

// OpenPersister opens (or creates) a BadgerDB at dir and returns a Persister.
// The caller must Close it on shutdown.
func OpenPersister(dir string) (*Persister, error) {
	opts := badger.DefaultOptions(dir).WithLogger(nil)
	db, err := badger.Open(opts)
	if err != nil {
		return nil, err
	}
	return &Persister{db: db}, nil
}

// Close releases the underlying BadgerDB. Safe to call after Run has returned.
func (p *Persister) Close() error {
	if p.db == nil {
		return nil
	}
	return p.db.Close()
}

// Save serializes snap as JSON and writes it under snapshotKey, overwriting any
// previous snapshot.
func (p *Persister) Save(snap types.GraphUpdatePayload) error {
	buf, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	return p.db.Update(func(txn *badger.Txn) error {
		return txn.Set(snapshotKey, buf)
	})
}

// Load returns the most recently saved snapshot. If no snapshot has been
// written yet, it returns an empty payload (and a nil error) so callers can
// treat first-boot identically to crash-recovery.
func (p *Persister) Load() (types.GraphUpdatePayload, error) {
	var out types.GraphUpdatePayload
	err := p.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(snapshotKey)
		if err != nil {
			if errors.Is(err, badger.ErrKeyNotFound) {
				return nil
			}
			return err
		}
		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &out)
		})
	})
	if err != nil {
		return types.GraphUpdatePayload{}, err
	}
	return out, nil
}

// Run drives a snapshot ticker until ctx is cancelled. Every interval it takes
// a fresh Snapshot from g and writes it via Save. Save errors are not fatal;
// the goroutine continues so a transient disk issue does not stall the engine.
func (p *Persister) Run(ctx context.Context, g *Graph, interval time.Duration) {
	if interval <= 0 {
		interval = time.Second
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if err := p.Save(g.Snapshot()); err == nil && p.onSaved != nil {
				p.onSaved()
			}
		}
	}
}
