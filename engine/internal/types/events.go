package types

import "time"

type ProcessCreate struct {
	EventID     string
	TS          time.Time
	Host        string
	PID         int
	Image       string
	ParentPID   int
	ParentImage string
	CommandLine string
	User        string
}

type NetworkConnect struct {
	EventID  string
	TS       time.Time
	Host     string
	PID      int
	Image    string
	DstIP    string
	DstPort  int
	Protocol string
}

type LogonSuccess struct {
	EventID       string
	TS            time.Time
	Host          string
	TargetUser    string
	TargetDomain  string
	TargetSID     string
	TargetLogonID string
	LogonType     int
	LogonProcess  string
	AuthPackage   string
	Workstation   string
	IPAddress     string
	IPPort        int
	SubjectUser   string
	SubjectDomain string
	SubjectLogonID string
}

type LogonFailure struct {
	EventID         string
	TS              time.Time
	Host            string
	TargetUser      string
	TargetDomain    string
	LogonType       int
	Status          string
	SubStatus       string
	FailureReason   string
	Workstation     string
	IPAddress       string
	IPPort          int
	SubjectUser     string
	SubjectDomain   string
}

type SpecialLogon struct {
	EventID        string
	TS             time.Time
	Host           string
	SubjectUser    string
	SubjectDomain  string
	SubjectSID     string
	SubjectLogonID string
	Privileges     string
}

type KerberosTGT struct {
	EventID          string
	TS               time.Time
	Host             string
	TargetUser       string
	TargetDomain     string
	TargetSID        string
	ServiceName      string
	IPAddress        string
	IPPort           int
	Status           string
	TicketOptions    string
	TicketEncryption string
	PreAuthType      string
}

type KerberosService struct {
	EventID          string
	TS               time.Time
	Host             string
	TargetUser       string
	TargetDomain     string
	ServiceName      string
	ServiceSID       string
	IPAddress        string
	IPPort           int
	Status           string
	TicketOptions    string
	TicketEncryption string
}

type ADEvent struct {
	EventID        string
	TS             time.Time
	Host           string
	ObjectType     string
	Operation      string
	Target         string
	TargetDomain   string
	TargetSID      string
	Member         string
	MemberSID      string
	Actor          string
	ActorDomain    string
	ActorSID       string
	Attribute      string
	AttributeValue string
}

type ProcessAccess struct {
	EventID       string
	TS            time.Time
	Host          string
	SourcePID     int
	SourceImage   string
	SourceUser    string
	TargetPID     int
	TargetImage   string
	TargetUser    string
	GrantedAccess string
	CallTrace     string
}

type FileCreate struct {
	EventID        string
	TS             time.Time
	Host           string
	PID            int
	Image          string
	User           string
	TargetFilename string
}
