package schema

import (
	"fmt"

	"github.com/luigifernandez/unravel/engine/internal/types"
)

// ParseWinSec dispatches to the per-EID parser based on the raw event's
// EventID/EventCode field. Returns the typed event as any so the caller can
// type-switch. Returns ErrUnsupportedEvent for recognized Windows Security
// events the engine does not care about.
func ParseWinSec(raw map[string]any) (any, error) {
	eid := asString(raw, "EventID")
	if eid == "" {
		eid = asString(raw, "EventCode")
	}
	switch eid {
	case "4624":
		return ParseLogonSuccess(raw)
	case "4625":
		return ParseLogonFailure(raw)
	case "4672":
		return ParseSpecialLogon(raw)
	case "4768":
		return ParseKerberosTGT(raw)
	case "4769":
		return ParseKerberosService(raw)
	case "":
		return nil, fmt.Errorf("missing EventID/EventCode")
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedEvent, eid)
	}
}

func ParseLogonSuccess(raw map[string]any) (types.LogonSuccess, error) {
	ts, err := parseTime(raw, "")
	if err != nil {
		return types.LogonSuccess{}, err
	}
	logonType, err := asInt(raw, "LogonType")
	if err != nil {
		return types.LogonSuccess{}, fmt.Errorf("LogonSuccess: %w", err)
	}
	return types.LogonSuccess{
		EventID:        eventID(raw),
		TS:             ts,
		Host:           hostFrom(raw),
		TargetUser:     asString(raw, "TargetUserName"),
		TargetDomain:   asString(raw, "TargetDomainName"),
		TargetSID:      asString(raw, "TargetUserSid"),
		TargetLogonID:  asString(raw, "TargetLogonId"),
		LogonType:      logonType,
		LogonProcess:   asString(raw, "LogonProcessName"),
		AuthPackage:    asString(raw, "AuthenticationPackageName"),
		Workstation:    asString(raw, "WorkstationName"),
		IPAddress:      asString(raw, "IpAddress"),
		IPPort:         asIntOpt(raw, "IpPort"),
		SubjectUser:    asString(raw, "SubjectUserName"),
		SubjectDomain:  asString(raw, "SubjectDomainName"),
		SubjectLogonID: asString(raw, "SubjectLogonId"),
	}, nil
}

func ParseLogonFailure(raw map[string]any) (types.LogonFailure, error) {
	ts, err := parseTime(raw, "")
	if err != nil {
		return types.LogonFailure{}, err
	}
	logonType, err := asInt(raw, "LogonType")
	if err != nil {
		return types.LogonFailure{}, fmt.Errorf("LogonFailure: %w", err)
	}
	return types.LogonFailure{
		EventID:       eventID(raw),
		TS:            ts,
		Host:          hostFrom(raw),
		TargetUser:    asString(raw, "TargetUserName"),
		TargetDomain:  asString(raw, "TargetDomainName"),
		LogonType:     logonType,
		Status:        asString(raw, "Status"),
		SubStatus:     asString(raw, "SubStatus"),
		FailureReason: asString(raw, "FailureReason"),
		Workstation:   asString(raw, "WorkstationName"),
		IPAddress:     asString(raw, "IpAddress"),
		IPPort:        asIntOpt(raw, "IpPort"),
		SubjectUser:   asString(raw, "SubjectUserName"),
		SubjectDomain: asString(raw, "SubjectDomainName"),
	}, nil
}

func ParseSpecialLogon(raw map[string]any) (types.SpecialLogon, error) {
	ts, err := parseTime(raw, "")
	if err != nil {
		return types.SpecialLogon{}, err
	}
	return types.SpecialLogon{
		EventID:        eventID(raw),
		TS:             ts,
		Host:           hostFrom(raw),
		SubjectUser:    asString(raw, "SubjectUserName"),
		SubjectDomain:  asString(raw, "SubjectDomainName"),
		SubjectSID:     asString(raw, "SubjectUserSid"),
		SubjectLogonID: asString(raw, "SubjectLogonId"),
		Privileges:     asString(raw, "PrivilegeList"),
	}, nil
}

func ParseKerberosTGT(raw map[string]any) (types.KerberosTGT, error) {
	ts, err := parseTime(raw, "")
	if err != nil {
		return types.KerberosTGT{}, err
	}
	return types.KerberosTGT{
		EventID:          eventID(raw),
		TS:               ts,
		Host:             hostFrom(raw),
		TargetUser:       asString(raw, "TargetUserName"),
		TargetDomain:     asString(raw, "TargetDomainName"),
		TargetSID:        asString(raw, "TargetSid"),
		ServiceName:      asString(raw, "ServiceName"),
		IPAddress:        asString(raw, "IpAddress"),
		IPPort:           asIntOpt(raw, "IpPort"),
		Status:           asString(raw, "Status"),
		TicketOptions:    asString(raw, "TicketOptions"),
		TicketEncryption: asString(raw, "TicketEncryptionType"),
		PreAuthType:      asString(raw, "PreAuthType"),
	}, nil
}

func ParseKerberosService(raw map[string]any) (types.KerberosService, error) {
	ts, err := parseTime(raw, "")
	if err != nil {
		return types.KerberosService{}, err
	}
	return types.KerberosService{
		EventID:          eventID(raw),
		TS:               ts,
		Host:             hostFrom(raw),
		TargetUser:       asString(raw, "TargetUserName"),
		TargetDomain:     asString(raw, "TargetDomainName"),
		ServiceName:      asString(raw, "ServiceName"),
		ServiceSID:       asString(raw, "ServiceSid"),
		IPAddress:        asString(raw, "IpAddress"),
		IPPort:           asIntOpt(raw, "IpPort"),
		Status:           asString(raw, "Status"),
		TicketOptions:    asString(raw, "TicketOptions"),
		TicketEncryption: asString(raw, "TicketEncryptionType"),
	}, nil
}
