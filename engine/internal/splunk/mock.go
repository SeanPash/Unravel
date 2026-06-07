package splunk

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"
)

// timelineEntry is the on-disk shape MockSource consumes. A timeline file is a
// JSON array of these; each entry tags a raw Splunk event with the source it
// came from so the pipeline can dispatch to the right schema parser.
type timelineEntry struct {
	Kind  SourceKind     `json:"source"`
	Event map[string]any `json:"event"`
}

// MockSource replays a timeline of canned events at a configurable speed. Used
// by all unit tests, the e2e smoke test, and `--mode=replay` in production.
type MockSource struct {
	events   []RawEvent
	speed    float64
	out      chan RawEvent
	closeCh  chan struct{}
	closeOnce sync.Once
	now      func() time.Time
	sleep    func(time.Duration)
}

// MockOption configures a MockSource at construction.
type MockOption func(*MockSource)

// WithReplaySpeed sets the timeline playback multiplier. 1.0 reproduces the
// recorded gaps in real time; 0 (the default) emits events as fast as the
// consumer can read them, which keeps unit tests fast.
func WithReplaySpeed(speed float64) MockOption {
	return func(m *MockSource) { m.speed = speed }
}

// withClock injects deterministic time sources for tests. Not exported because
// production code never needs to override the wall clock.
func withClock(now func() time.Time, sleep func(time.Duration)) MockOption {
	return func(m *MockSource) {
		m.now = now
		m.sleep = sleep
	}
}

// NewMockFromFiles reads each timeline file, merges all entries, sorts them by
// _time, and returns a Source ready to stream. Call Start to begin emission.
func NewMockFromFiles(paths []string, opts ...MockOption) (*MockSource, error) {
	var all []timelineEntry
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", p, err)
		}
		var entries []timelineEntry
		if err := json.Unmarshal(b, &entries); err != nil {
			return nil, fmt.Errorf("decode %s: %w", p, err)
		}
		all = append(all, entries...)
	}
	return newMock(all, opts...)
}

// NewMockFromEntries is the in-memory constructor — handy for table tests that
// don't want to round-trip through disk.
func NewMockFromEntries(kindEvents []RawEvent, opts ...MockOption) *MockSource {
	m := &MockSource{
		events:  append([]RawEvent(nil), kindEvents...),
		out:     make(chan RawEvent),
		closeCh: make(chan struct{}),
		now:     time.Now,
		sleep:   time.Sleep,
	}
	for _, opt := range opts {
		opt(m)
	}
	sort.SliceStable(m.events, func(i, j int) bool {
		return m.events[i].TS.Before(m.events[j].TS)
	})
	return m
}

func newMock(entries []timelineEntry, opts ...MockOption) (*MockSource, error) {
	events := make([]RawEvent, 0, len(entries))
	for i, e := range entries {
		ts, err := extractTime(e.Event)
		if err != nil {
			return nil, fmt.Errorf("entry %d (%s): %w", i, e.Kind, err)
		}
		events = append(events, RawEvent{Kind: e.Kind, TS: ts, Raw: e.Event})
	}
	return NewMockFromEntries(events, opts...), nil
}

// Events returns the channel the pipeline reads from. The channel closes when
// the timeline is exhausted or Close is called.
func (m *MockSource) Events() <-chan RawEvent { return m.out }

// Close stops emission and closes the events channel. Safe to call more than once.
func (m *MockSource) Close() error {
	m.closeOnce.Do(func() { close(m.closeCh) })
	return nil
}

// Start launches the emission goroutine. Returns immediately; the caller reads
// from Events. Calling Start more than once is a programming error.
func (m *MockSource) Start() {
	go m.run()
}

func (m *MockSource) run() {
	defer close(m.out)
	if len(m.events) == 0 {
		return
	}
	first := m.events[0].TS
	start := m.now()
	for _, e := range m.events {
		if m.speed > 0 {
			elapsed := e.TS.Sub(first)
			target := start.Add(time.Duration(float64(elapsed) / m.speed))
			if wait := target.Sub(m.now()); wait > 0 {
				if !m.sleepInterruptible(wait) {
					return
				}
			}
		}
		select {
		case m.out <- e:
		case <-m.closeCh:
			return
		}
	}
}

// sleepInterruptible waits up to d but returns false if Close fires first. The
// real time.Sleep is the typical implementation; tests inject a hook.
func (m *MockSource) sleepInterruptible(d time.Duration) bool {
	if m.sleep != nil && d > 0 {
		done := make(chan struct{})
		go func() {
			m.sleep(d)
			close(done)
		}()
		select {
		case <-done:
			return true
		case <-m.closeCh:
			return false
		}
	}
	return true
}

// extractTime mirrors schema.parseTime but stays in the splunk package so this
// file has no dependency cycle with schema. Tries _time then UtcTime then
// TimeGenerated (the AD audit channel uses the last).
func extractTime(raw map[string]any) (time.Time, error) {
	for _, key := range []string{"_time", "UtcTime", "TimeGenerated"} {
		if v, ok := raw[key]; ok && v != nil {
			if t, err := coerceTime(v); err == nil {
				return t, nil
			}
		}
	}
	return time.Time{}, fmt.Errorf("no parseable timestamp")
}

func coerceTime(v any) (time.Time, error) {
	switch x := v.(type) {
	case string:
		layouts := []string{
			time.RFC3339Nano,
			time.RFC3339,
			"2006-01-02 15:04:05.000",
			"2006-01-02 15:04:05",
		}
		for _, layout := range layouts {
			if t, err := time.Parse(layout, x); err == nil {
				return t.UTC(), nil
			}
		}
	case float64:
		sec := int64(x)
		nsec := int64((x - float64(sec)) * 1e9)
		return time.Unix(sec, nsec).UTC(), nil
	}
	return time.Time{}, fmt.Errorf("unrecognized time")
}
