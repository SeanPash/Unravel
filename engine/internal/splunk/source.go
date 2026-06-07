// Package splunk defines the engine's event Source interface and two
// implementations: MockSource for hermetic replay of canned timelines, and
// RESTSource for streaming consume from a live Splunk instance via the
// services/search/jobs/export endpoint. Both produce RawEvent values on a
// channel the pipeline reads from.
package splunk

import "time"

// SourceKind names the upstream log source a RawEvent originated from. The
// pipeline uses it to dispatch to the matching schema parser.
type SourceKind string

const (
	SourceSysmon  SourceKind = "sysmon"
	SourceWinsec  SourceKind = "winsec"
	SourceADAudit SourceKind = "adaudit"
)

// RawEvent is the schema-agnostic envelope flowing out of any Source. Raw is
// the decoded JSON payload as Splunk emitted it; the engine's schema package
// turns it into a typed event keyed by Kind.
type RawEvent struct {
	Kind SourceKind
	TS   time.Time
	Raw  map[string]any
}

// Source is the streaming-event abstraction shared by Mock and REST sources.
// Close must be safe to call concurrently with reads on Events.
type Source interface {
	Events() <-chan RawEvent
	Close() error
}
