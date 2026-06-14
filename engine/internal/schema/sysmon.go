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
	eid := firstField(raw, "EventID", "EventCode", "event_id", "signature_id")
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
	pid, err := firstInt(raw, "ProcessId", "process_id", "pid")
	if err != nil {
		return types.ProcessCreate{}, fmt.Errorf("ProcessCreate: %w", err)
	}
	return types.ProcessCreate{
		EventID:     eventID(raw),
		TS:          ts,
		Host:        hostFrom(raw),
		PID:         pid,
		Image:       firstField(raw, "Image", "process", "process_path", "Process_Name", "process_exec"),
		ParentPID:   firstIntOpt(raw, "ParentProcessId", "parent_process_id", "ppid"),
		ParentImage: firstField(raw, "ParentImage", "parent_process", "parent_process_path", "parent_process_name"),
		CommandLine: firstField(raw, "CommandLine", "process_command_line", "Process_Command_Line", "process"),
		User:        firstField(raw, "User", "user", "Account_Name", "src_user"),
	}, nil
}

func ParseNetworkConnect(raw map[string]any) (types.NetworkConnect, error) {
	ts, err := parseTime(raw, "UtcTime")
	if err != nil {
		return types.NetworkConnect{}, err
	}
	pid, err := firstInt(raw, "ProcessId", "process_id", "pid")
	if err != nil {
		return types.NetworkConnect{}, fmt.Errorf("NetworkConnect: %w", err)
	}
	dport, err := firstInt(raw, "DestinationPort", "dest_port", "dport")
	if err != nil {
		return types.NetworkConnect{}, fmt.Errorf("NetworkConnect: %w", err)
	}
	return types.NetworkConnect{
		EventID:  eventID(raw),
		TS:       ts,
		Host:     hostFrom(raw),
		PID:      pid,
		Image:    firstField(raw, "Image", "process", "process_path", "Process_Name"),
		DstIP:    firstField(raw, "DestinationIp", "dest_ip", "dest"),
		DstPort:  dport,
		Protocol: firstField(raw, "Protocol", "transport", "protocol"),
	}, nil
}

func ParseProcessAccess(raw map[string]any) (types.ProcessAccess, error) {
	ts, err := parseTime(raw, "UtcTime")
	if err != nil {
		return types.ProcessAccess{}, err
	}
	srcPID, err := firstInt(raw, "SourceProcessId", "source_process_id")
	if err != nil {
		return types.ProcessAccess{}, fmt.Errorf("ProcessAccess: %w", err)
	}
	tgtPID, err := firstInt(raw, "TargetProcessId", "dest_process_id")
	if err != nil {
		return types.ProcessAccess{}, fmt.Errorf("ProcessAccess: %w", err)
	}
	return types.ProcessAccess{
		EventID:       eventID(raw),
		TS:            ts,
		Host:          hostFrom(raw),
		SourcePID:     srcPID,
		SourceImage:   firstField(raw, "SourceImage", "process", "process_path"),
		SourceUser:    firstField(raw, "SourceUser", "user"),
		TargetPID:     tgtPID,
		TargetImage:   firstField(raw, "TargetImage", "dest_process"),
		TargetUser:    firstField(raw, "TargetUser"),
		GrantedAccess: firstField(raw, "GrantedAccess"),
		CallTrace:     firstField(raw, "CallTrace"),
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
	pid, err := firstInt(raw, "ProcessId", "process_id", "pid")
	if err != nil {
		return types.FileCreate{}, fmt.Errorf("FileCreate: %w", err)
	}
	return types.FileCreate{
		EventID:        eventID(raw),
		TS:             ts,
		Host:           hostFrom(raw),
		PID:            pid,
		Image:          firstField(raw, "Image", "process", "process_path"),
		User:           firstField(raw, "User", "user"),
		TargetFilename: firstField(raw, "TargetFilename", "file_path", "file_name"),
	}, nil
}
