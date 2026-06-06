package schema

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Splunk export emits most field values as strings, but _time can be a float
// (epoch seconds) and some integrations send numerics as native JSON numbers.
// These helpers coerce defensively without losing precision on integer IDs.

func asString(raw map[string]any, key string) string {
	v, ok := raw[key]
	if !ok || v == nil {
		return ""
	}
	switch x := v.(type) {
	case string:
		return x
	case float64:
		// Format without trailing zeros for integer-valued floats.
		if x == float64(int64(x)) {
			return strconv.FormatInt(int64(x), 10)
		}
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	default:
		return fmt.Sprintf("%v", x)
	}
}

func asInt(raw map[string]any, key string) (int, error) {
	v, ok := raw[key]
	if !ok || v == nil {
		return 0, fmt.Errorf("missing field %q", key)
	}
	switch x := v.(type) {
	case string:
		s := strings.TrimSpace(x)
		if s == "" {
			return 0, fmt.Errorf("empty field %q", key)
		}
		// Accept hex (e.g. "0x1010") for GrantedAccess-style fields.
		if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
			n, err := strconv.ParseInt(s[2:], 16, 64)
			if err != nil {
				return 0, fmt.Errorf("parse hex %q: %w", key, err)
			}
			return int(n), nil
		}
		n, err := strconv.Atoi(s)
		if err != nil {
			return 0, fmt.Errorf("parse int %q: %w", key, err)
		}
		return n, nil
	case float64:
		return int(x), nil
	default:
		return 0, fmt.Errorf("field %q has unsupported type %T", key, v)
	}
}

// asIntOpt returns 0 if missing rather than erroring. Use for non-critical fields.
func asIntOpt(raw map[string]any, key string) int {
	n, err := asInt(raw, key)
	if err != nil {
		return 0
	}
	return n
}

// parseTime tries _time first (preferred — Splunk's authoritative timestamp),
// falling back to a Sysmon UtcTime-style field. Returns zero time + error if
// neither is parseable.
func parseTime(raw map[string]any, fallbackKey string) (time.Time, error) {
	if v, ok := raw["_time"]; ok && v != nil {
		switch x := v.(type) {
		case string:
			if t, err := parseFlexibleTime(x); err == nil {
				return t, nil
			}
		case float64:
			sec := int64(x)
			nsec := int64((x - float64(sec)) * 1e9)
			return time.Unix(sec, nsec).UTC(), nil
		}
	}
	if fallbackKey != "" {
		if s := asString(raw, fallbackKey); s != "" {
			if t, err := parseFlexibleTime(s); err == nil {
				return t, nil
			}
		}
	}
	return time.Time{}, fmt.Errorf("no parseable timestamp (_time or %q)", fallbackKey)
}

func parseFlexibleTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.000",
		"2006-01-02 15:04:05",
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	// Splunk also gives "_time" as an epoch string sometimes.
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		sec := int64(f)
		nsec := int64((f - float64(sec)) * 1e9)
		return time.Unix(sec, nsec).UTC(), nil
	}
	return time.Time{}, fmt.Errorf("unrecognized time format: %q", s)
}

// hostFrom returns host with fallbacks (Splunk uses "host", winlogbeat ships
// "ComputerName" in the event payload).
func hostFrom(raw map[string]any) string {
	if s := asString(raw, "host"); s != "" {
		return s
	}
	return asString(raw, "ComputerName")
}

// eventID returns a stable identifier for the raw event. Splunk's RecordNumber
// is per-source-monotonic; fall back to UtcTime + EventID composite if absent.
func eventID(raw map[string]any) string {
	if s := asString(raw, "RecordNumber"); s != "" {
		return s
	}
	return asString(raw, "EventID") + "@" + asString(raw, "UtcTime")
}
