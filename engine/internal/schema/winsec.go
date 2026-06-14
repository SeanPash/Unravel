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
	eid := firstField(raw, "EventID", "EventCode", "event_id", "signature_id")
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
	logonType, err := firstInt(raw, "LogonType", "Logon_Type", "logon_type")
	if err != nil {
		return types.LogonSuccess{}, fmt.Errorf("LogonSuccess: %w", err)
	}
	return types.LogonSuccess{
		EventID:        eventID(raw),
		TS:             ts,
		Host:           hostFrom(raw),
		TargetUser:     firstField(raw, "TargetUserName", "user", "Account_Name", "Target_Account_Name"),
		TargetDomain:   firstField(raw, "TargetDomainName", "Target_Domain"),
		TargetSID:      firstField(raw, "TargetUserSid", "user_id"),
		TargetLogonID:  firstField(raw, "TargetLogonId"),
		LogonType:      logonType,
		LogonProcess:   firstField(raw, "LogonProcessName"),
		AuthPackage:    firstField(raw, "AuthenticationPackageName"),
		Workstation:    firstField(raw, "WorkstationName", "src_nt_host"),
		IPAddress:      firstField(raw, "IpAddress", "src_ip", "src"),
		IPPort:         firstIntOpt(raw, "IpPort", "src_port"),
		SubjectUser:    firstField(raw, "SubjectUserName"),
		SubjectDomain:  firstField(raw, "SubjectDomainName"),
		SubjectLogonID: firstField(raw, "SubjectLogonId"),
	}, nil
}

func ParseLogonFailure(raw map[string]any) (types.LogonFailure, error) {
	ts, err := parseTime(raw, "")
	if err != nil {
		return types.LogonFailure{}, err
	}
	logonType, err := firstInt(raw, "LogonType", "Logon_Type", "logon_type")
	if err != nil {
		return types.LogonFailure{}, fmt.Errorf("LogonFailure: %w", err)
	}
	return types.LogonFailure{
		EventID:       eventID(raw),
		TS:            ts,
		Host:          hostFrom(raw),
		TargetUser:    firstField(raw, "TargetUserName", "user", "Account_Name"),
		TargetDomain:  firstField(raw, "TargetDomainName"),
		LogonType:     logonType,
		Status:        firstField(raw, "Status"),
		SubStatus:     firstField(raw, "SubStatus"),
		FailureReason: firstField(raw, "FailureReason"),
		Workstation:   firstField(raw, "WorkstationName", "src_nt_host"),
		IPAddress:     firstField(raw, "IpAddress", "src_ip", "src"),
		IPPort:        firstIntOpt(raw, "IpPort", "src_port"),
		SubjectUser:   firstField(raw, "SubjectUserName"),
		SubjectDomain: firstField(raw, "SubjectDomainName"),
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
		SubjectUser:    firstField(raw, "SubjectUserName", "user", "Account_Name"),
		SubjectDomain:  firstField(raw, "SubjectDomainName"),
		SubjectSID:     firstField(raw, "SubjectUserSid", "user_id"),
		SubjectLogonID: firstField(raw, "SubjectLogonId"),
		Privileges:     firstField(raw, "PrivilegeList", "Privileges"),
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
		TargetUser:       firstField(raw, "TargetUserName", "user", "Account_Name"),
		TargetDomain:     firstField(raw, "TargetDomainName"),
		TargetSID:        firstField(raw, "TargetSid", "user_id"),
		ServiceName:      firstField(raw, "ServiceName"),
		IPAddress:        firstField(raw, "IpAddress", "src_ip", "src"),
		IPPort:           firstIntOpt(raw, "IpPort", "src_port"),
		Status:           firstField(raw, "Status"),
		TicketOptions:    firstField(raw, "TicketOptions"),
		TicketEncryption: firstField(raw, "TicketEncryptionType"),
		PreAuthType:      firstField(raw, "PreAuthType"),
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
		TargetUser:       firstField(raw, "TargetUserName", "user", "Account_Name"),
		TargetDomain:     firstField(raw, "TargetDomainName"),
		ServiceName:      firstField(raw, "ServiceName"),
		ServiceSID:       firstField(raw, "ServiceSid"),
		IPAddress:        firstField(raw, "IpAddress", "src_ip", "src"),
		IPPort:           firstIntOpt(raw, "IpPort", "src_port"),
		Status:           firstField(raw, "Status"),
		TicketOptions:    firstField(raw, "TicketOptions"),
		TicketEncryption: firstField(raw, "TicketEncryptionType"),
	}, nil
}
