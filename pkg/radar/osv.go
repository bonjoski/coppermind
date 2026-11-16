package radar

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type osvResponse struct {
	Vulns []osvVulnerability `json:"vulns"`
}

type osvVulnerability struct {
	ID        string         `json:"id"`
	Summary   string         `json:"summary"`
	Details   string         `json:"details"`
	Aliases   []string       `json:"aliases"`
	Published string         `json:"published"`
	Modified  string         `json:"modified"`
	Affected  []osvAffected  `json:"affected"`
	Severity  []osvSeverity  `json:"severity"`
}

type osvAffected struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// OSVAdapter queries the OSV.dev API or parses OSV JSON responses.
type OSVAdapter struct {
	Client *http.Client
}

func (a *OSVAdapter) Type() string {
	return "osv-stream"
}

func (a *OSVAdapter) Fetch(ctx context.Context, config FeedConfig) ([]RawItem, error) {
	if config.URL == "" {
		return nil, fmt.Errorf("osv adapter: url is required")
	}

	client := a.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}

	eco := config.Ecosystem
	switch strings.ToLower(eco) {
	case "golang":
		eco = "Go"
	case "rust":
		eco = "crates.io"
	case "jvm":
		eco = "Maven"
	case "node-typescript":
		eco = "npm"
	case "dotnet":
		eco = "NuGet"
	case "python":
		eco = "PyPI"
	}

	var req *http.Request
	var err error

	if strings.HasSuffix(config.URL, "/query") {
		payload := map[string]interface{}{
			"package": map[string]string{
				"ecosystem": eco,
			},
		}
		jsonBytes, _ := json.Marshal(payload)
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, config.URL, bytes.NewReader(jsonBytes))
		if err != nil {
			return nil, fmt.Errorf("failed to create osv request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
	} else {
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, config.URL, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create osv request: %w", err)
		}
	}

	req.Header.Set("User-Agent", "Coppermind-Radar/1.0 (Zero-Trust Feed Ingest)")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("osv fetch failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("osv server returned HTTP %d", resp.StatusCode)
	}

	limitedReader := io.LimitReader(resp.Body, 10*1024*1024)
	body, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read osv response body: %w", err)
	}

	return a.ParseJSON(config.ID, body)
}

// ParseJSON parses raw OSV JSON payload into RawItems.
func (a *OSVAdapter) ParseJSON(feedID string, body []byte) ([]RawItem, error) {
	var resp osvResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		var single osvVulnerability
		if singleErr := json.Unmarshal(body, &single); singleErr == nil && single.ID != "" {
			resp.Vulns = []osvVulnerability{single}
		} else {
			return nil, fmt.Errorf("failed to unmarshal osv json: %w", err)
		}
	}

	var items []RawItem
	for _, v := range resp.Vulns {
		pubTime, _ := time.Parse(time.RFC3339, v.Published)
		if pubTime.IsZero() {
			pubTime = time.Now().UTC()
		}

		cveAlias := ""
		for _, alias := range v.Aliases {
			if strings.HasPrefix(alias, "CVE-") {
				cveAlias = alias
				break
			}
		}

		pkgNames := make([]string, 0, len(v.Affected))
		for _, aff := range v.Affected {
			if aff.Package.Name != "" {
				pkgNames = append(pkgNames, aff.Package.Name)
			}
		}

		title := v.Summary
		if title == "" {
			title = fmt.Sprintf("Advisory %s", v.ID)
		}
		if cveAlias != "" {
			title = fmt.Sprintf("[%s / %s] %s", v.ID, cveAlias, title)
		} else {
			title = fmt.Sprintf("[%s] %s", v.ID, title)
		}

		desc := v.Details
		if desc == "" {
			desc = v.Summary
		}
		rawBody := fmt.Sprintf("Advisory: %s\nAliases: %s\nAffected Packages: %s\nDetails: %s",
			v.ID, strings.Join(v.Aliases, ", "), strings.Join(pkgNames, ", "), desc)

		items = append(items, RawItem{
			FeedID:      feedID,
			ExternalID:  v.ID,
			Title:       title,
			RawBody:     strings.TrimSpace(rawBody),
			URL:         fmt.Sprintf("https://osv.dev/vulnerability/%s", v.ID),
			PublishedAt: pubTime,
		})
	}

	return items, nil
}

func init() {
	Register(&OSVAdapter{})
}
