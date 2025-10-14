package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/api/bsky"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/bluesky-social/indigo/xrpc"
	"github.com/golang-jwt/jwt/v4"
)

// Global constants for file names and sizes
const (
	authFile      = "bsky_auth.json"
	didFileName   = "user_did.txt"
	feedFileName  = "custom_feed.json"
	maxFeedSize   = 1 * 1024 * 1024 // 1 MB
)

// Global constants for HTTP headers and values
const (
	contentTypeHeader  = "Content-Type"
	contentTypeValue   = "application/json"
	lastModifiedHeader = "Last-Modified"
	cacheControlHeader = "Cache-Control"
	httpTimeFormat     = http.TimeFormat
)

// BSkyFeed defines the JSON structure for the final output feed.
type BSkyFeed struct {
	Feed []BSkyFeedItem `json:"feed"`
}

// BSkyFeedItem defines an individual post item in the feed skeleton format.
type BSkyFeedItem struct {
	Post   string           `json:"post"`
	Reason *json.RawMessage `json:"reason,omitempty"`
}

// PostItem includes a timestamp for internal processing
type PostItem struct {
	Post      string           `json:"post"`
	Reason    *json.RawMessage `json:"reason,omitempty"`
	CreatedAt time.Time        `json:"createdAt"`
}

// IntermediateFeed defines the JSON structure for the intermediate data.
type IntermediateFeed struct {
	Feed []PostItem `json:"feed"`
}

// FeedConfig maps a feed ID to its corresponding DID list file.
type FeedConfig struct {
	FeedID  string
	DIDFile string
}

// BskyClient wraps the atproto client and manages its session state.
type BskyClient struct {
	mu              sync.RWMutex // Protects the client and session data
	client          *xrpc.Client
	sessionStoreDir string
	tokenExpiresAt  time.Time
}

// NewBskyClient constructs a new BskyClient and attempts to login.
func NewBskyClient(ctx context.Context, sessionStoreDir string) (*BskyClient, error) {
	b := &BskyClient{
		client:          &xrpc.Client{Host: "https://bsky.social"},
		sessionStoreDir: sessionStoreDir,
	}

	if err := b.login(ctx); err != nil {
		return nil, err
	}

	// Start background refresh loop
	go b.refreshSessionLoop(ctx)

	return b, nil
}

// login handles initial authentication or re-authentication.
func (b *BskyClient) login(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	// 1. Attempt to load and refresh existing session
	authPath := filepath.Join(b.sessionStoreDir, authFile)
	authData, err := os.ReadFile(authPath)
	if err == nil {
		var auth xrpc.AuthInfo
		if err := json.Unmarshal(authData, &auth); err == nil {
			b.client.Auth = &auth
			b.updateTokenExpiration()
			log.Println("Loaded existing session from file.")

			// NOTE: using refresh in access location for "refreshSession" call
			b.client.Auth.AccessJwt = b.client.Auth.RefreshJwt

			// Try to refresh with a timeout context
			refreshCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			renewed, refreshErr := atproto.ServerRefreshSession(refreshCtx, b.client)
			if refreshErr == nil {
				b.client.Auth.AccessJwt = renewed.AccessJwt
				b.client.Auth.RefreshJwt = renewed.RefreshJwt
				b.updateTokenExpiration()
				b.saveAuthInfo()
				log.Println("Session refreshed successfully on startup.")
				return nil
			}
			log.Printf("Failed to refresh session on startup (%v), will attempt full login.", refreshErr)
		}
	}

	// 2. Fallback: Perform a full new session login
	handle := os.Getenv("BSKY_ID")
	password := os.Getenv("BSKY_APPPASSWORD")
	if handle == "" || password == "" {
		return fmt.Errorf("BSKY_ID and BSKY_APPPASSWORD environment variables must be set")
	}

	createCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	output, err := atproto.ServerCreateSession(createCtx, b.client, &atproto.ServerCreateSession_Input{
		Identifier: handle,
		Password:   password,
	})
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	b.client.Auth = &xrpc.AuthInfo{
		Handle:     output.Handle,
		Did:        output.Did,
		AccessJwt:  output.AccessJwt,
		RefreshJwt: output.RefreshJwt,
	}
	b.updateTokenExpiration()
	log.Println("New session created.")
	return b.saveAuthInfo()
}

func (b *BskyClient) updateTokenExpiration() {
	if b.client.Auth == nil {
		return
	}
	token, _ := jwt.Parse(b.client.Auth.AccessJwt, nil)
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		if exp, ok := claims["exp"].(float64); ok {
			b.tokenExpiresAt = time.Unix(int64(exp), 0)
		}
	}
}

func (b *BskyClient) saveAuthInfo() error {
	authJson, err := json.Marshal(b.client.Auth)
	if err != nil {
		return fmt.Errorf("failed to marshal auth info: %w", err)
	}
	authPath := filepath.Join(b.sessionStoreDir, authFile)
	if err := os.WriteFile(authPath, authJson, 0644); err != nil {
		return fmt.Errorf("failed to write auth file: %w", err)
	}
	return nil
}

// refreshSessionLoop handles background token refreshing.
func (b *BskyClient) refreshSessionLoop(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Println("Context cancelled, stopping refresh session loop.")
			return
		case <-ticker.C:
			b.mu.Lock()
			// Refresh token 5 minutes before it expires
			if b.tokenExpiresAt.Before(time.Now().Add(5 * time.Minute)) {
				log.Println("Access token is about to expire, attempting to refresh...")
				// NOTE: using refresh in access location for "refreshSession" call
				b.client.Auth.AccessJwt = b.client.Auth.RefreshJwt
				renewed, err := atproto.ServerRefreshSession(ctx, b.client)
				if err == nil {
					b.client.Auth.AccessJwt = renewed.AccessJwt
					b.client.Auth.RefreshJwt = renewed.RefreshJwt
					b.updateTokenExpiration()
					b.saveAuthInfo()
					log.Println("Session refreshed successfully.")
				} else {
					log.Printf("Session refresh failed: %v. Attempting full re-login...", err)
					// If refresh fails, try a full login as a fallback
					b.mu.Unlock() // Unlock before recursive call
					b.login(ctx) // Pass the context to the login call
					b.mu.Lock()  // Re-acquire lock
				}
			}
			b.mu.Unlock()
		}
	}
}

// GetClient provides a thread-safe way to get the client instance.
func (b *BskyClient) GetClient() *xrpc.Client {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.client
}

// FeedsRefresher handles the periodic refresh of feeds.
type FeedsRefresher struct {
	cache       *FileCache
	feeds       []FeedConfig
	bskyClient  *BskyClient
	updateMutex sync.Mutex
}

func NewFeedsRefresher(feeds []FeedConfig, client *BskyClient, cache *FileCache) *FeedsRefresher {
	return &FeedsRefresher{
		cache:      cache,
		feeds:      feeds,
		bskyClient: client,
	}
}

// Start refreshes feeds periodically.
func (f *FeedsRefresher) Start(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	f.refreshAllFeeds(ctx)

	for {
		select {
		case <-ctx.Done():
			log.Println("Context cancelled, stopping feed refresher loop.")
			return
		case <-ticker.C:
			f.refreshAllFeeds(ctx)
		}
	}
}

func (f *FeedsRefresher) refreshAllFeeds(ctx context.Context) {
	f.updateMutex.Lock()
	defer f.updateMutex.Unlock()

	log.Println("Starting scheduled feed refresh...")
	for _, feed := range f.feeds {
		if err := f.refreshFeed(ctx, feed); err != nil {
			log.Printf("Error refreshing feed %s: %v", feed.FeedID, err)
		}
	}
	log.Println("Scheduled feed refresh completed.")
}

func (f *FeedsRefresher) refreshFeed(ctx context.Context, feedCfg FeedConfig) error {
	log.Printf("Refreshing feed: %s", feedCfg.FeedID)

	feedDir := filepath.Join(f.cache.feedsDir, feedCfg.FeedID)
	if err := os.MkdirAll(feedDir, 0755); err != nil {
		return fmt.Errorf("failed to create feed directory: %w", err)
	}

	didFile := filepath.Join(feedDir, feedCfg.DIDFile)
	dids, err := f.loadDIDs(didFile)
	if err != nil {
		return fmt.Errorf("failed to load DIDs from %s: %w", didFile, err)
	}

	feedPath := filepath.Join(feedDir, feedFileName)

	latestTime := time.Now().Add(-7 * 24 * time.Hour)
	var existingPosts *IntermediateFeed

	if _, err := os.Stat(feedPath); err == nil {
		existingPosts, err = f.loadIntermediateFeed(feedPath)
		if err == nil && len(existingPosts.Feed) > 0 {
			latestTime = existingPosts.Feed[0].CreatedAt
		} else if err != nil {
			log.Printf("Warning: Failed to load existing feed from %s, starting from scratch: %v", feedPath, err)
		}
	}
	
	newPosts, err := f.fetchPosts(ctx, dids, latestTime) // Pass context here
	if err != nil {
		return fmt.Errorf("failed to fetch posts: %w", err)
	}

	if len(newPosts) == 0 {
		log.Printf("No new posts found for feed %s. Skipping file update.", feedCfg.FeedID)
		return nil
	}

	combinedPosts := combineAndFilterPosts(newPosts, existingPosts)
	if err := f.saveIntermediateFeed(combinedPosts, feedPath); err != nil {
		return fmt.Errorf("failed to save feed: %w", err)
	}

	f.cache.Invalidate(feedCfg.FeedID)

	log.Printf("Feed %s updated successfully with %d posts.", feedCfg.FeedID, len(combinedPosts.Feed))
	return nil
}

func (f *FeedsRefresher) loadDIDs(filePath string) ([]string, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read DID file: %w", err)
	}
	var dids []string
	for _, line := range strings.Split(string(content), "\n") {
		did := strings.TrimSpace(line)
		if did != "" {
			dids = append(dids, did)
		}
	}
	return dids, nil
}

// getPostTime parses the correct timestamp for a given feed item, handling reposts.
func getPostTime(item *bsky.FeedDefs_FeedViewPost) time.Time {
	var createdAt time.Time
	// If the reason is a repost, use its IndexedAt time.
	if item.Reason != nil && item.Reason.FeedDefs_ReasonRepost != nil {
		t, err := time.Parse(time.RFC3339, item.Reason.FeedDefs_ReasonRepost.IndexedAt)
		if err == nil {
			createdAt = t
		}
	}

	// If not a repost or if parsing failed, try to get the post's creation time.
	if createdAt.IsZero() && item.Post != nil && item.Post.Record != nil && item.Post.Record.Val != nil {
		if post, ok := item.Post.Record.Val.(*bsky.FeedPost); ok && post != nil {
			t, err := time.Parse(time.RFC3339, post.CreatedAt)
			if err == nil {
				createdAt = t
			}
		}
	}
	return createdAt
}

// MinimalRepostReason defines the simplified JSON structure for a repost reason
type MinimalRepostReason struct {
	Type   string `json:"$type"`
	Repost string `json:"repost"`
}

// fetchPosts fetches posts for a list of DIDs, stopping at a given timestamp.
func (f *FeedsRefresher) fetchPosts(ctx context.Context, dids []string, latestTime time.Time) ([]PostItem, error) {
	log.Printf("Fetching posts since: %s", latestTime.Format(time.RFC3339))
	uniquePostsMap := make(map[string]PostItem)

	didsSet := make(map[string]struct{})
	for _, did := range dids {
		didsSet[did] = struct{}{}
	}

	for i, did := range dids {
		log.Printf("Fetching posts for DID: %s (%d/%d)", did, i+1, len(dids))
		cursor := ""

	FetchDIDLoop:
		for {
			// Pass the context to the API call
			resp, err := bsky.FeedGetAuthorFeed(ctx, f.bskyClient.GetClient(), did, cursor, "", false, int64(30))
			if err != nil {
				log.Printf("Error fetching feed for %s: %v", did, err)
				break
			}

			if len(resp.Feed) == 0 {
				break
			}

			// Sort the fetched posts by time in descending order
			sort.Slice(resp.Feed, func(i, j int) bool {
				return getPostTime(resp.Feed[i]).After(getPostTime(resp.Feed[j]))
			})

			for _, item := range resp.Feed {
				createdAt := getPostTime(item)

				if createdAt.IsZero() {
					continue
				}

				if !createdAt.After(latestTime) {
					break FetchDIDLoop
				}

				if item.Reply != nil && item.Reply.Parent != nil {
					if parentPost := item.Reply.Parent.FeedDefs_PostView; parentPost != nil {
						parentUri, err := syntax.ParseATURI(parentPost.Uri)
						if err != nil {
							log.Printf("Error parsing parent URI: %v", err)
							continue
						}
						parentDid := parentUri.Authority().String()
						if _, ok := didsSet[parentDid]; !ok {
							log.Printf("Skipping reply to %s (not in target DIDs).", parentDid)
							continue
						}
					}
				}

				existingPost, ok := uniquePostsMap[item.Post.Uri]
				if !ok || createdAt.After(existingPost.CreatedAt) {
					var reasonJSON *json.RawMessage
					if item.Reason != nil && item.Reason.FeedDefs_ReasonRepost != nil {
						// Manually create the reason with the correct skeleton type
						repostReason := MinimalRepostReason{
							Type:   "app.bsky.feed.defs#skeletonReasonRepost",
							Repost: *item.Reason.FeedDefs_ReasonRepost.Uri,
						}
						jsonBytes, err := json.Marshal(repostReason)
						if err == nil {
							raw := json.RawMessage(jsonBytes)
							reasonJSON = &raw
						} else {
							log.Printf("Error marshalling minimal repost reason: %v", err)
						}
					}

					uniquePostsMap[item.Post.Uri] = PostItem{
						Post:      item.Post.Uri,
						Reason:    reasonJSON,
						CreatedAt: createdAt,
					}
				}
			}

			if resp.Cursor == nil || *resp.Cursor == "" {
				break
			}
			cursor = *resp.Cursor
		}

		if i < len(dids)-1 {
			log.Println("Waiting 1 second to respect rate limits...")
			// Use a select statement to wait, allowing for context cancellation.
			select {
			case <-time.After(1 * time.Second):
				// Wait completed.
			case <-ctx.Done():
				// Context cancelled, stop immediately.
				log.Println("Context cancelled during rate limit sleep, returning early.")
				return nil, ctx.Err()
			}
		}
	}

	finalFeedSlice := make([]PostItem, 0, len(uniquePostsMap))
	for _, p := range uniquePostsMap {
		finalFeedSlice = append(finalFeedSlice, p)
	}

	sort.Slice(finalFeedSlice, func(i, j int) bool {
		return finalFeedSlice[i].CreatedAt.After(finalFeedSlice[j].CreatedAt)
	})

	return finalFeedSlice, nil
}

func combineAndFilterPosts(newPosts []PostItem, existingFeed *IntermediateFeed) *IntermediateFeed {
	combined := newPosts
	newPostURIs := make(map[string]struct{})
	for _, p := range newPosts {
		newPostURIs[p.Post] = struct{}{}
	}

	if existingFeed != nil {
		for _, p := range existingFeed.Feed {
			if _, ok := newPostURIs[p.Post]; !ok {
				combined = append(combined, p)
			}
		}
	}

	return &IntermediateFeed{Feed: combined}
}

func (f *FeedsRefresher) loadIntermediateFeed(filePath string) (*IntermediateFeed, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var feedData IntermediateFeed
	if err := json.NewDecoder(file).Decode(&feedData); err != nil {
		return nil, fmt.Errorf("failed to decode intermediate feed JSON: %w", err)
	}
	return &feedData, nil
}

func (f *FeedsRefresher) saveIntermediateFeed(feed *IntermediateFeed, filePath string) error {
	feedJSON, err := json.Marshal(feed)
	if err != nil {
		return fmt.Errorf("failed to marshal intermediate feed: %w", err)
	}

	feedJSON = limitJSONSize(feedJSON, maxFeedSize)

	if err := os.WriteFile(filePath, feedJSON, 0644); err != nil {
		return fmt.Errorf("failed to write auth file: %w", err)
	}
	return nil
}

func limitJSONSize(data []byte, limit int) []byte {
	if len(data) <= limit {
		return data
	}

	var tempFeed IntermediateFeed
	if err := json.Unmarshal(data, &tempFeed); err != nil {
		return data
	}

	for i := len(tempFeed.Feed); i > 0; i-- {
		truncatedFeed := &IntermediateFeed{Feed: tempFeed.Feed[:i]}
		truncatedJSON, _ := json.Marshal(truncatedFeed)
		if len(truncatedJSON) <= limit {
			return truncatedJSON
		}
	}
	return []byte("{\"feed\":[]}")
}

// FileCache manages the in-memory cache for feed files.
type FileCache struct {
	sync.RWMutex
	data     map[string]*CachedData
	feedsDir string
}

type CachedData struct {
	Feed    *BSkyFeed
	LastMod time.Time
}

func NewFileCache(dir string) *FileCache {
	return &FileCache{
		data:     make(map[string]*CachedData),
		feedsDir: dir,
	}
}

// GetFeed retrieves and caches the feed from a file.
func (c *FileCache) GetFeed(feedName string) (*BSkyFeed, error) {
	c.Lock()
	defer c.Unlock()

	filePath := filepath.Join(c.feedsDir, feedName, feedFileName)

	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("bsky feed file not found: %w", err)
	}

	if cached, ok := c.data[feedName]; ok {
		if fileInfo.ModTime().Equal(cached.LastMod) || fileInfo.ModTime().Before(cached.LastMod) {
			log.Printf("Using cached data for bsky feed: %s", feedName)
			return cached.Feed, nil
		}
	}

	log.Printf("Reloading bsky feed from file: %s", filePath)
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open bsky feed file: %w", err)
	}
	defer file.Close()

	var intermediateFeed IntermediateFeed
	if err := json.NewDecoder(file).Decode(&intermediateFeed); err != nil {
		return nil, fmt.Errorf("failed to decode JSON: %w", err)
	}

	// Convert intermediate feed to final bsky feed format
	var feedData BSkyFeed
	for _, item := range intermediateFeed.Feed {
		feedData.Feed = append(feedData.Feed, BSkyFeedItem{
			Post:   item.Post,
			Reason: item.Reason,
		})
	}

	c.data[feedName] = &CachedData{
		Feed:    &feedData,
		LastMod: fileInfo.ModTime(),
	}

	return &feedData, nil
}

func (c *FileCache) Invalidate(feedName string) {
	c.Lock()
	defer c.Unlock()
	delete(c.data, feedName)
}

// feedHandler handles the HTTP request for the feed skeleton. It now takes the maxAge for Cache-Control.
func feedHandler(cache *FileCache, maxAge time.Duration) http.HandlerFunc {
	// build Cache-Control header value
	cacheControlValue := fmt.Sprintf("public, max-age=%d", int(maxAge.Seconds()))

	return func(w http.ResponseWriter, r *http.Request) {
		feedParam := r.URL.Query().Get("feed")
		if feedParam == "" {
			http.Error(w, "query parameter 'feed' is required", http.StatusBadRequest)
			return
		}

		parts := strings.Split(feedParam, "/")
		feedName := parts[len(parts)-1]

		filePath := filepath.Join(cache.feedsDir, feedName, feedFileName)
		fileInfo, err := os.Stat(filePath)
		if err != nil {
			http.Error(w, "feed file not found", http.StatusNotFound)
			return
		}

		if sinceHeader := r.Header.Get("If-Modified-Since"); sinceHeader != "" {
			sinceTime, err := time.Parse(httpTimeFormat, sinceHeader)
			if err == nil && !fileInfo.ModTime().After(sinceTime) {
				log.Printf("File not modified: %s. Returning 304.", feedName)
				w.WriteHeader(http.StatusNotModified)
				return
			}
		}

		limitStr := r.URL.Query().Get("limit")
		cursorStr := r.URL.Query().Get("cursor")

		feed, err := cache.GetFeed(feedName)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		start := 0
		if cursorStr != "" {
			for i, item := range feed.Feed {
				if item.Post == cursorStr {
					start = i + 1
					break
				}
			}
		}

		end := len(feed.Feed)
		if limitStr != "" {
			var limit int
			fmt.Sscanf(limitStr, "%d", &limit)
			if start+limit < end {
				end = start + limit
			}
		}

		postsToReturn := feed.Feed[start:end]
		response := map[string]interface{}{
			"feed": postsToReturn,
		}

		if end < len(feed.Feed) {
			response["cursor"] = feed.Feed[end-1].Post
		}

		w.Header().Set(lastModifiedHeader, fileInfo.ModTime().UTC().Format(httpTimeFormat))
		w.Header().Set(cacheControlHeader, cacheControlValue)
		w.Header().Set(contentTypeHeader, contentTypeValue)

		json.NewEncoder(w).Encode(response)
	}
}

// discoverFeeds scans the feeds directory and returns a list of FeedConfig.
func discoverFeeds(feedsDir string) ([]FeedConfig, error) {
	entries, err := os.ReadDir(feedsDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read feeds directory: %w", err)
	}

	var configs []FeedConfig
	for _, entry := range entries {
		if entry.IsDir() {
			feedID := entry.Name()
			didFilePath := filepath.Join(feedsDir, feedID, didFileName)
			if _, err := os.Stat(didFilePath); err == nil {
				configs = append(configs, FeedConfig{
					FeedID:  feedID,
					DIDFile: didFileName,
				})
			}
		}
	}
	return configs, nil
}

func main() {
	// Command-line flags
	feedsDir := flag.String("feeds-dir", "./feeds", "Directory to store feed data")
	refreshIntervalSec := flag.Int("refresh-interval", 900, "Feed refresh interval in seconds")
	port := flag.Int("port", 8080, "Port to serve the feed on")
	flag.Parse()

	refreshInterval := time.Duration(*refreshIntervalSec) * time.Second

	if err := os.MkdirAll(*feedsDir, 0755); err != nil {
		log.Fatalf("Failed to create feeds directory: %v", err)
	}

	feedConfigs, err := discoverFeeds(*feedsDir)
	if err != nil {
		log.Fatalf("Failed to discover feeds: %v", err)
	}

	if len(feedConfigs) == 0 {
		log.Println("No feeds found. Please create a subdirectory with a 'user_did.txt' file inside the './feeds' directory.")
	} else {
		log.Printf("Discovered %d feeds to serve.", len(feedConfigs))
	}

	// Create a root context that can be cancelled
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // Ensure context is cancelled on main function exit

	bskyClient, err := NewBskyClient(ctx, *feedsDir)
	if err != nil {
		log.Fatalf("Failed to initialize Bluesky client: %v", err)
	}

	cache := NewFileCache(*feedsDir)
	refresher := NewFeedsRefresher(feedConfigs, bskyClient, cache)

	// Pass context to the refresher to allow for graceful shutdown
	go refresher.Start(ctx, refreshInterval)

	http.HandleFunc("/xrpc/app.bsky.feed.getFeedSkeleton", feedHandler(cache, refreshInterval))
	log.Printf("Starting bsky feed-daemon on port %d...", *port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", *port), nil))
}
