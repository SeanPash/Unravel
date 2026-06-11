package intel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMockSourceReadsFixtures(t *testing.T) {
	m := NewMockSource("../../testdata")
	kev, err := m.KEV(context.Background(), "lsass")
	if err != nil {
		t.Fatalf("KEV: %v", err)
	}
	if len(kev) == 0 || !kev[0].InKEV {
		t.Errorf("expected KEV rows flagged InKEV, got %+v", kev)
	}
	cve, err := m.CVE(context.Background(), "kerberos")
	if err != nil {
		t.Fatalf("CVE: %v", err)
	}
	if len(cve) == 0 || cve[0].ID == "" {
		t.Errorf("expected CVE rows with IDs, got %+v", cve)
	}
}

func TestRESTSourceParsesKEVAndNVD(t *testing.T) {
	kevSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"vulnerabilities":[
			{"cveID":"CVE-2020-1472","vulnerabilityName":"Zerologon","shortDescription":"Netlogon EoP"},
			{"cveID":"CVE-2019-0708","vulnerabilityName":"BlueKeep","shortDescription":"RDP RCE"}
		]}`))
	}))
	defer kevSrv.Close()

	nvdSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("keywordSearch") == "" {
			t.Error("expected keywordSearch query param")
		}
		_, _ = w.Write([]byte(`{"vulnerabilities":[
			{"cve":{"id":"CVE-2022-33679","descriptions":[{"lang":"en","value":"Kerberos EoP"}],
			 "metrics":{"cvssMetricV31":[{"cvssData":{"baseSeverity":"HIGH"}}]}}}
		]}`))
	}))
	defer nvdSrv.Close()

	s := NewRESTSource(RESTConfig{KEVURL: kevSrv.URL, NVDURL: nvdSrv.URL})

	kev, err := s.KEV(context.Background(), "zerologon")
	if err != nil {
		t.Fatalf("KEV: %v", err)
	}
	if len(kev) != 1 || kev[0].ID != "CVE-2020-1472" || !kev[0].InKEV {
		t.Errorf("KEV filter wrong: %+v", kev)
	}

	cve, err := s.CVE(context.Background(), "kerberos")
	if err != nil {
		t.Fatalf("CVE: %v", err)
	}
	if len(cve) != 1 || cve[0].ID != "CVE-2022-33679" || cve[0].Severity != "HIGH" {
		t.Errorf("CVE parse wrong: %+v", cve)
	}
}
