package schema

import (
	"fmt"

	"github.com/luigifernandez/unravel/engine/internal/types"
)

// ParseADAudit dispatches to the per-EID parser for Windows AD object change
// events. Returns the typed event as any so the caller can type-switch. Returns
// ErrUnsupportedEvent for AD audit EIDs the engine does not care about.
func ParseADAudit(raw map[string]any) (any, error) {
	eid := asString(raw, "EventID")
	if eid == "" {
		eid = asString(raw, "EventCode")
	}
	switch eid {
	case "4720":
		return ParseUserCreated(raw)
	case "4728":
		return ParseGlobalGroupMemberAdded(raw)
	case "4732":
		return ParseLocalGroupMemberAdded(raw)
	case "5136":
		return ParseDirectoryObjectModified(raw)
	case "":
		return nil, fmt.Errorf("missing EventID/EventCode")
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedEvent, eid)
	}
}

func ParseUserCreated(raw map[string]any) (types.ADEvent, error) {
	ts, err := parseTime(raw, "")
	if err != nil {
		return types.ADEvent{}, err
	}
	return types.ADEvent{
		EventID:      eventID(raw),
		TS:           ts,
		Host:         hostFrom(raw),
		ObjectType:   "User",
		Operation:    "Created",
		Target:       asString(raw, "TargetUserName"),
		TargetDomain: asString(raw, "TargetDomainName"),
		TargetSID:    asString(raw, "TargetSid"),
		Actor:        asString(raw, "SubjectUserName"),
		ActorDomain:  asString(raw, "SubjectDomainName"),
		ActorSID:     asString(raw, "SubjectUserSid"),
	}, nil
}

func ParseGlobalGroupMemberAdded(raw map[string]any) (types.ADEvent, error) {
	return parseGroupMemberAdded(raw, "GlobalGroup")
}

func ParseLocalGroupMemberAdded(raw map[string]any) (types.ADEvent, error) {
	return parseGroupMemberAdded(raw, "LocalGroup")
}

func parseGroupMemberAdded(raw map[string]any, objectType string) (types.ADEvent, error) {
	ts, err := parseTime(raw, "")
	if err != nil {
		return types.ADEvent{}, err
	}
	return types.ADEvent{
		EventID:      eventID(raw),
		TS:           ts,
		Host:         hostFrom(raw),
		ObjectType:   objectType,
		Operation:    "MemberAdded",
		Target:       asString(raw, "TargetUserName"),
		TargetDomain: asString(raw, "TargetDomainName"),
		TargetSID:    asString(raw, "TargetSid"),
		Member:       asString(raw, "MemberName"),
		MemberSID:    asString(raw, "MemberSid"),
		Actor:        asString(raw, "SubjectUserName"),
		ActorDomain:  asString(raw, "SubjectDomainName"),
		ActorSID:     asString(raw, "SubjectUserSid"),
	}, nil
}

func ParseDirectoryObjectModified(raw map[string]any) (types.ADEvent, error) {
	ts, err := parseTime(raw, "")
	if err != nil {
		return types.ADEvent{}, err
	}
	objectType := asString(raw, "ObjectClass")
	if objectType == "" {
		objectType = "DirectoryObject"
	}
	return types.ADEvent{
		EventID:        eventID(raw),
		TS:             ts,
		Host:           hostFrom(raw),
		ObjectType:     objectType,
		Operation:      "Modified",
		Target:         asString(raw, "ObjectDN"),
		Attribute:      asString(raw, "AttributeLDAPDisplayName"),
		AttributeValue: asString(raw, "AttributeValue"),
		Actor:          asString(raw, "SubjectUserName"),
		ActorDomain:    asString(raw, "SubjectDomainName"),
		ActorSID:       asString(raw, "SubjectUserSid"),
	}, nil
}
