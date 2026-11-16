package radar

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type cisaKEVResponse struct {
	Title           string             `json:"title"`
	Count           int                `json:"count"`
	Vulnerabilities []cisaKEVItemEntry `json:"vulnerabilities"`
}

type cisaKEVItemEntry struct {
	CVEID                      string `json:"cveID"`
	VendorProject              string `json:"vendorProject"`
	Product                    string `json:"product"`
	VulnerabilityName          string `json:"vulnerabilityName"`
	DateAdded                  string `json:"dateAdded"`
	ShortDescription           string `json:"shortDescription"`
	RequiredAction             string `json:"requiredAction"`
	DueDate                    string `json:"dueDate"`
	KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
	Notes                      string `json:"notes"`
}

// CISAKEVAdapter parses the CISA Known Exploited Vulnerabilities catalog.
type CISAKEVAdapter struct {
	Client *http.Client
}

func (a *CISAKEVAdapter) Type() string {
	return "cisa-kev"
}

func (a *CISAKEVAdapter) Fetch(ctx context.Context, config FeedConfig) ([]RawItem, error) {
	if config.URL == "" {
		return nil, fmt.Errorf("cisa-kev adapter: url is required")
	}

	client := a.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, config.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create http request: %w", err)
	}
	req.Header.Set("User-Agent", "Coppermind-Radar/1.0 (Zero-Trust Feed Ingest)")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cisa-kev fetch failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("cisa-kev server returned HTTP %d", resp.StatusCode)
	}

	limitedReader := io.LimitReader(resp.Body, 10*1024*1024)
	body, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	return a.ParseJSON(config.ID, body)
}

// ParseJSON parses raw JSON into RawItems.
func (a *CISAKEVAdapter) ParseJSON(feedID string, body []byte) ([]RawItem, error) {
	var catalog cisaKEVResponse
	if err := json.Unmarshal(body, &catalog); err != nil {
		return nil, fmt.Errorf("failed to unmarshal cisa-kev json: %w", err)
	}

	var items []RawItem
	for _, v := range catalog.Vulnerabilities {
		pubTime, _ := time.Parse("2006-01-02", v.DateAdded)
		if pubTime.IsZero() {
			pubTime = time.Now().UTC()
		}

		rawBody := fmt.Sprintf("Vendor: %s\nProduct: %s\nVulnerability: %s\nDescription: %s\nRequired Action: %s\nRansomware Use: %s",
			v.VendorProject, v.Product, v.VulnerabilityName, v.ShortDescription, v.RequiredAction, v.KnownRansomwareCampaignUse)

		items = append(items, RawItem{
			FeedID:      feedID,
			ExternalID:  v.CVEID,
			Title:       fmt.Sprintf("[%s] %s %s - %s", v.CVEID, v.VendorProject, v.Product, v.VulnerabilityName),
			RawBody:     strings.TrimSpace(rawBody),
			URL:         fmt.Sprintf("https://www.cve.org/CVERecord?id=%s", v.CVEID),
			PublishedAt: pubTime,
		})
	}

	return items, nil
}

func init() {
	Register(&CISAKEVAdapter{})
}
