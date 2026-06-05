package schema

import (
	"errors"
	"fmt"

	"github.com/luigifernandez/unravel/engine/internal/types"
)

// ErrUnsupportedEvent is returned by ParseSysmon when the event ID is recognized
// as Sysmon but isn't one the engine cares about. The pipeline should treat it
// as a skip, not a hard error.
var ErrUnsupportedEvent = errors.New("unsupported sysmon event id")

// ParseSysmon dispatches to the per-EID parser based on the raw event's
// EventID/EventCode field. Returns the typed event as any so the caller can
// type-switch.
func ParseSysmon(raw map[string]any) (any, error) {
	eid := asString(raw, "EventID")
	if eid == "" {
		eid = asString(raw, "EventCode")
	}
	switch eid {
	case "1":
		return ParseProcessCreate(raw)
	case "3":
		return ParseNetworkConnect(raw)
	case "10":
		return ParseProcessAccess(raw)
	case "11":
		return ParseFileCreate(raw)
	case "":
		return nil, fmt.Errorf("missing EventID/EventCode")
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedEvent, eid)
	}
}

func ParseProcessCreate(raw map[string]any) (types.ProcessCreate, error) {
	ts, err := parseTime(raw, "UtcTime")
	if err != nil {
		return types.ProcessCreate{}, err
	}
	pid, err := asInt(raw, "ProcessId")
	if err != nil {
		return types.ProcessCreate{}, fmt.Errorf("ProcessCreate: %w", err)
	}
	return types.ProcessCreate{
		EventID:     eventID(raw),
		TS:          ts,
		Host:        hostFrom(raw),
		PID:         pid,
		Image:       asString(raw, "Image"),
		ParentPID:   asIntOpt(raw, "ParentProcessId"),
		ParentImage: asString(raw, "ParentImage"),
		CommandLine: asString(raw, "CommandLine"),
		User:        asString(raw, "User"),
	}, nil
}

func ParseNetworkConnect(raw map[string]any) (types.NetworkConnect, error) {
	ts, err := parseTime(raw, "UtcTime")
	if err != nil {
		return types.NetworkConnect{}, err
	}
	pid, err := asInt(raw, "ProcessId")
	if err != nil {
		return types.NetworkConnect{}, fmt.Errorf("NetworkConnect: %w", err)
	}
	dport, err := asInt(raw, "DestinationPort")
	if err != nil {
		return types.NetworkConnect{}, fmt.Errorf("NetworkConnect: %w", err)
	}
	return types.NetworkConnect{
		EventID:  eventID(raw),
		TS:       ts,
		Host:     hostFrom(raw),
		PID:      pid,
		Image:    asString(raw, "Image"),
		DstIP:    asString(raw, "DestinationIp"),
		DstPort:  dport,
		Protocol: asString(raw, "Protocol"),
	}, nil
}

func ParseProcessAccess(raw map[string]any) (types.ProcessAccess, error) {
	ts, err := parseTime(raw, "UtcTime")
	if err != nil {
		return types.ProcessAccess{}, err
	}
	srcPID, err := asInt(raw, "SourceProcessId")
	if err != nil {
		return types.ProcessAccess{}, fmt.Errorf("ProcessAccess: %w", err)
	}
	tgtPID, err := asInt(raw, "TargetProcessId")
	if err != nil {
		return types.ProcessAccess{}, fmt.Errorf("ProcessAccess: %w", err)
	}
	return types.ProcessAccess{
		EventID:       eventID(raw),
		TS:            ts,
		Host:          hostFrom(raw),
		SourcePID:     srcPID,
		SourceImage:   asString(raw, "SourceImage"),
		SourceUser:    asString(raw, "SourceUser"),
		TargetPID:     tgtPID,
		TargetImage:   asString(raw, "TargetImage"),
		TargetUser:    asString(raw, "TargetUser"),
		GrantedAccess: asString(raw, "GrantedAccess"),
		CallTrace:     asString(raw, "CallTrace"),
	}, nil
}

func ParseFileCreate(raw map[string]any) (types.FileCreate, error) {
	ts, err := parseTime(raw, "CreationUtcTime")
	if err != nil {
		// CreationUtcTime is the file's mtime, not the event time; fall back to UtcTime.
		ts, err = parseTime(raw, "UtcTime")
		if err != nil {
			return types.FileCreate{}, err
		}
	}
	pid, err := asInt(raw, "ProcessId")
	if err != nil {
		return types.FileCreate{}, fmt.Errorf("FileCreate: %w", err)
	}
	return types.FileCreate{
		EventID:        eventID(raw),
		TS:             ts,
		Host:           hostFrom(raw),
		PID:            pid,
		Image:          asString(raw, "Image"),
		User:           asString(raw, "User"),
		TargetFilename: asString(raw, "TargetFilename"),
	}, nil
}
