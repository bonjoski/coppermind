package radar

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type rssFeed struct {
	Channel struct {
		Title string    `xml:"title"`
		Items []rssItem `xml:"item"`
	} `xml:"channel"`
}

type rssItem struct {
	Title       string `xml:"title"`
	Link        string `xml:"link"`
	Description string `xml:"description"`
	PubDate     string `xml:"pubDate"`
	GUID        string `xml:"guid"`
}

type atomFeed struct {
	Title   string      `xml:"title"`
	Entries []atomEntry `xml:"entry"`
}

type atomEntry struct {
	Title   string     `xml:"title"`
	Link    atomLink   `xml:"link"`
	Summary string     `xml:"summary"`
	Content string     `xml:"content"`
	Updated string     `xml:"updated"`
	ID      string     `xml:"id"`
}

type atomLink struct {
	Href string `xml:"href,attr"`
}

// RSSAdapter fetches and parses RSS and Atom feeds.
type RSSAdapter struct {
	Client *http.Client
}

func (a *RSSAdapter) Type() string {
	return "rss"
}

func (a *RSSAdapter) Fetch(ctx context.Context, config FeedConfig) ([]RawItem, error) {
	if config.URL == "" {
		return nil, fmt.Errorf("rss adapter: url is required")
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
		return nil, fmt.Errorf("rss fetch failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("rss server returned HTTP %d", resp.StatusCode)
	}

	limitedReader := io.LimitReader(resp.Body, 10*1024*1024)
	body, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	return a.ParseXML(config.ID, body)
}

// ParseXML parses raw XML (RSS or Atom) into RawItems.
func (a *RSSAdapter) ParseXML(feedID string, body []byte) ([]RawItem, error) {
	// Attempt RSS 2.0 parsing first
	var rss rssFeed
	if err := xml.Unmarshal(body, &rss); err == nil && len(rss.Channel.Items) > 0 {
		var items []RawItem
		for _, it := range rss.Channel.Items {
			pubTime := parseFlexTime(it.PubDate)
			extID := it.GUID
			if extID == "" {
				extID = it.Link
			}
			items = append(items, RawItem{
				FeedID:      feedID,
				ExternalID:  extID,
				Title:       strings.TrimSpace(it.Title),
				RawBody:     strings.TrimSpace(it.Description),
				URL:         strings.TrimSpace(it.Link),
				PublishedAt: pubTime,
			})
		}
		return items, nil
	}

	// Attempt Atom parsing
	var atom atomFeed
	if err := xml.Unmarshal(body, &atom); err == nil && len(atom.Entries) > 0 {
		var items []RawItem
		for _, entry := range atom.Entries {
			pubTime := parseFlexTime(entry.Updated)
			bodyText := entry.Summary
			if bodyText == "" {
				bodyText = entry.Content
			}
			extID := entry.ID
			if extID == "" {
				extID = entry.Link.Href
			}
			items = append(items, RawItem{
				FeedID:      feedID,
				ExternalID:  extID,
				Title:       strings.TrimSpace(entry.Title),
				RawBody:     strings.TrimSpace(bodyText),
				URL:         strings.TrimSpace(entry.Link.Href),
				PublishedAt: pubTime,
			})
		}
		return items, nil
	}

	return nil, fmt.Errorf("failed to parse XML payload as either RSS or Atom format")
}

func parseFlexTime(s string) time.Time {
	formats := []string{
		time.RFC1123Z,
		time.RFC1123,
		time.RFC3339,
		time.RFC3339Nano,
		"Mon, 02 Jan 2006 15:04:05 -0700",
		"2006-01-02T15:04:05Z",
		"2006-01-02",
	}
	s = strings.TrimSpace(s)
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return t
		}
	}
	return time.Now().UTC()
}

func init() {
	Register(&RSSAdapter{})
}
