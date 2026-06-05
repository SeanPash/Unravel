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

type Auth struct {
	EventID   string
	TS        time.Time
	Host      string
	User      string
	LogonType int
	EventCode int
	Source    string
}

type ADEvent struct {
	EventID    string
	TS         time.Time
	Host       string
	ObjectType string
	Operation  string
	Target     string
	Actor      string
}
