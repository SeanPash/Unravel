package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/luigifernandez/unravel/engine/internal/types"
)

const (
	defaultKEVURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	defaultNVDURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
)

// RESTConfig configures the live source. URLs default to the public endpoints;
// tests override them. NVDKey, when set, is sent as the apiKey header to lift
// the NVD rate limit.
//
// TLS verification is always enforced here: CISA KEV and NVD are public,
// CA-signed endpoints, so there is no legitimate reason to skip verification.
// Deliberately no Insecure knob.
type RESTConfig struct {
	KEVURL     string
	NVDURL     string
	NVDKey     string
	HTTPClient *http.Client
}

// RESTSource fetches the CISA KEV catalog (once, cached for the process
// lifetime) and queries the NVD CVE API per keyword.
type RESTSource struct {
	cfg    RESTConfig
	client *http.Client

	once   sync.Once
	kev    []kevEntry
	kevErr error
}

func NewRESTSource(cfg RESTConfig) *RESTSource {
	if cfg.KEVURL == "" {
		cfg.KEVURL = defaultKEVURL
	}
	if cfg.NVDURL == "" {
		cfg.NVDURL = defaultNVDURL
	}
	client := cfg.HTTPClient
	if client == nil {
		// No Insecure path: these are public CA-signed endpoints, so TLS
		// verification stays on. Use the default transport's verification.
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return &RESTSource{cfg: cfg, client: client}
}

type kevEntry struct {
	CveID             string `json:"cveID"`
	VulnerabilityName string `json:"vulnerabilityName"`
	ShortDescription  string `json:"shortDescription"`
}

func (s *RESTSource) loadKEV(ctx context.Context) ([]kevEntry, error) {
	s.once.Do(func() {
		body, err := s.get(ctx, s.cfg.KEVURL)
		if err != nil {
			s.kevErr = err
			return
		}
		var doc struct {
			Vulnerabilities []kevEntry `json:"vulnerabilities"`
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			s.kevErr = fmt.Errorf("decode kev: %w", err)
			return
		}
		s.kev = doc.Vulnerabilities
	})
	return s.kev, s.kevErr
}

// KEV returns catalog entries whose name or description contains keyword.
func (s *RESTSource) KEV(ctx context.Context, keyword string) ([]types.CVEMatch, error) {
	entries, err := s.loadKEV(ctx)
	if err != nil {
		return nil, err
	}
	kw := strings.ToLower(keyword)
	var out []types.CVEMatch
	for _, e := range entries {
		hay := strings.ToLower(e.VulnerabilityName + " " + e.ShortDescription)
		if kw != "" && !strings.Contains(hay, kw) {
			continue
		}
		out = append(out, types.CVEMatch{
			ID:      e.CveID,
			Summary: e.ShortDescription,
			InKEV:   true,
		})
	}
	return out, nil
}

// CVE queries the NVD keyword search and maps the first results to CVEMatch.
func (s *RESTSource) CVE(ctx context.Context, keyword string) ([]types.CVEMatch, error) {
	u, err := url.Parse(s.cfg.NVDURL)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("keywordSearch", keyword)
	q.Set("resultsPerPage", "5")
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	if s.cfg.NVDKey != "" {
		req.Header.Set("apiKey", s.cfg.NVDKey)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("nvd request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("nvd status %d", resp.StatusCode)
	}

	var doc struct {
		Vulnerabilities []struct {
			CVE struct {
				ID           string `json:"id"`
				Descriptions []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
				Metrics struct {
					CvssV31 []struct {
						CvssData struct {
							BaseSeverity string `json:"baseSeverity"`
						} `json:"cvssData"`
					} `json:"cvssMetricV31"`
				} `json:"metrics"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("decode nvd: %w", err)
	}

	var out []types.CVEMatch
	for _, v := range doc.Vulnerabilities {
		m := types.CVEMatch{ID: v.CVE.ID}
		for _, d := range v.CVE.Descriptions {
			if d.Lang == "en" {
				m.Summary = d.Value
				break
			}
		}
		if len(v.CVE.Metrics.CvssV31) > 0 {
			m.Severity = v.CVE.Metrics.CvssV31[0].CvssData.BaseSeverity
		}
		out = append(out, m)
	}
	return out, nil
}

func (s *RESTSource) get(ctx context.Context, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("GET %s status %d", rawURL, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}
