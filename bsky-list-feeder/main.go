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

// Start handles the periodic refresh of feeds, including the first immediate refresh.
func (f *FeedsRefresher) Start(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Perform the initial refresh immediately (non-blocking from main's perspective)
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

	// Set a default latest time to fetch posts from the last 7 days
	latestTime := time.Now().Add(-7 * 24 * time.Hour) 
	var existingPosts *IntermediateFeed

	if _, err := os.Stat(feedPath); err == nil {
		// Attempt to load existing feed to find the latest post time
		existingPosts, err = f.loadIntermediateFeed(feedPath)
		if err == nil && len(existingPosts.Feed) > 0 {
			latestTime = existingPosts.Feed[0].CreatedAt
		} else if err != nil {
			log.Printf("Warning: Failed to load existing feed from %s, starting from scratch: %v", feedPath, err)
		}
	}
	
	newPosts, err := f.fetchPosts(ctx, dids, latestTime)
	if err != nil {
		return fmt.Errorf("failed to fetch posts: %w", err)
	}

	numNewPosts := len(newPosts) // Capture the number of new posts

	if numNewPosts == 0 {
		log.Printf("No new posts found for feed %s. Skipping file update.", feedCfg.FeedID)
		return nil
	}

	combinedPosts := combineAndFilterPosts(newPosts, existingPosts)
	
	// Pass the number of new posts to saveIntermediateFeed for size limiting
	if err := f.saveIntermediateFeed(combinedPosts, feedPath, numNewPosts); err != nil {
		return fmt.Errorf("failed to save feed: %w", err)
	}

	// Invalidate the cache to ensure the next request loads the new file
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

// normalizeTimestamp normalizes the fractional seconds part of an RFC3339 timestamp
// to fit time.RFC3339Nano (9 digits) by padding with zeros.
// Example: "2025-11-17T06:00:00.1Z" -> "2025-11-17T06:00:00.100000000Z"
func normalizeTimestamp(ts string) string {
	// Search for the timezone specification (Z or +/-hh:mm)
	tzIndex := strings.LastIndexFunc(ts, func(r rune) bool {
		return r == 'Z' || r == '+' || r == '-'
	})
	if tzIndex == -1 {
		return ts
	}

	// Search for the decimal point of the seconds part
	dotIndex := strings.LastIndex(ts[:tzIndex], ".")
	if dotIndex == -1 {
		// If no decimal point is found, return as is (time.RFC3339Nano can handle it)
		return ts
	}

	// Extract the fractional part of the seconds
	fractionalPart := ts[dotIndex+1 : tzIndex]
	
	// Number of digits in the fractional part
	numDigits := len(fractionalPart)

	// Pad with zeros to reach nanosecond precision (9 digits)
	if numDigits < 9 {
		padding := strings.Repeat("0", 9-numDigits)
		
		// Reconstruct the normalized string
		return ts[:dotIndex+1] + fractionalPart + padding + ts[tzIndex:]
	}

    // If 9 or more digits are present, return as is (RFC3339Nano handles up to 9)
	return ts
}


// getPostTime parses the correct timestamp for a given feed item, handling reposts.
func getPostTime(item *bsky.FeedDefs_FeedViewPost) time.Time {
	// 1. Check for Repost
	if item.Reason != nil && item.Reason.FeedDefs_ReasonRepost != nil {
		ts := item.Reason.FeedDefs_ReasonRepost.IndexedAt
		
		// Normalize the timestamp to handle variable fractional second precision,
		// then parse using RFC3339Nano.
		ts = normalizeTimestamp(ts)
		t, err := time.Parse(time.RFC3339Nano, ts)
		
		if err == nil {
			return t // Success: Return the Repost time (IndexedAt)
		}
		
		// Failure: Log the error and return a Zero value. This prevents the
		// incorrect fallback to the original post's old creation time.
		log.Printf("Warning: Failed to parse normalized repost time '%s': %v", ts, err)
		return time.Time{}
	}

	// 2. Check for Normal Post
	// Only look at the original post creation time if it is NOT a repost.
	if item.Post != nil && item.Post.Record != nil && item.Post.Record.Val != nil {
		if post, ok := item.Post.Record.Val.(*bsky.FeedPost); ok && post != nil {
			ts := post.CreatedAt
			
			// Apply normalization to the original post's timestamp as well.
			ts = normalizeTimestamp(ts)
			t, err := time.Parse(time.RFC3339Nano, ts)

			if err == nil {
				return t
			}
			
			// Log failure for original post's timestamp
			log.Printf("Warning: Failed to parse normalized post time '%s': %v", ts, err)
		}
	}
	
	// Return a Zero value if no valid timestamp could be extracted.
	return time.Time{}
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
			log.Println("Waiting 500 milliseconds to respect rate limits...")
			// Use a select statement to wait, allowing for context cancellation.
			select {
			case <-time.After(500 * time.Millisecond):
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

// saveIntermediateFeed saves the feed data using atomic write to prevent partial reads.
// It accepts the number of new posts added for size limiting logic.
func (f *FeedsRefresher) saveIntermediateFeed(feed *IntermediateFeed, filePath string, numNewPosts int) error {
	// The original feed is encoded once for size checking/limiting.
	feedJSON, err := json.Marshal(feed)
	if err != nil {
		return fmt.Errorf("failed to marshal intermediate feed: %w", err)
	}

	// Apply size limiting
	feedJSON = limitJSONSize(feedJSON, maxFeedSize, numNewPosts)

	// Implement Atomic Write
	tempPath := filePath + ".tmp"
    
    // 1. Write to a temporary file
	if err := os.WriteFile(tempPath, feedJSON, 0644); err != nil {
		return fmt.Errorf("failed to write temporary feed file: %w", err)
	}
    
    // 2. Atomically rename the temporary file to the final path
    // This ensures that readers only ever see a complete, finalized file.
	if err := os.Rename(tempPath, filePath); err != nil {
		return fmt.Errorf("failed to rename temp feed file: %w", err)
	}
    
	return nil
}

// limitJSONSize limits the size of the JSON data by truncating the post list using a simple, fast heuristic.
// It removes 'numNewPosts' posts from the oldest end if the limit is exceeded.
func limitJSONSize(data []byte, limit int, numNewPosts int) []byte {
	if len(data) <= limit {
		return data
	}

	var tempFeed IntermediateFeed
	if err := json.Unmarshal(data, &tempFeed); err != nil {
		// If unmarshal fails, return default empty feed
		return []byte("{\"feed\":[]}")
	}
    
    // Determine the number of posts to delete from the oldest end (tail of the array).
    numPosts := len(tempFeed.Feed)
    numToDelete := numNewPosts
    
    // Calculate the new length, ensuring it is not negative
    newLength := numPosts - numToDelete
    if newLength < 0 {
        newLength = 0
    }
    
    // Truncate the posts (removing the oldest ones)
	truncatedFeed := &IntermediateFeed{Feed: tempFeed.Feed[:newLength]}
    
    // Marshal the truncated result once
	truncatedJSON, err := json.Marshal(truncatedFeed)
    if err != nil {
        return []byte("{\"feed\":[]}")
    }
    
    // NOTE: Per user request, the final JSON size may still exceed the limit, 
    // but the truncation is performed based on the simplified heuristic.
    
    return truncatedJSON
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
		// File not found (e.g., initial startup before the first refresh)
		return nil, fmt.Errorf("bsky feed file not found: %w", err)
	}

	if cached, ok := c.data[feedName]; ok {
		// Check if the file modification time is the same or older than the cache.
		// os.Rename (atomic write) updates the ModTime, ensuring a reload when needed.
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

	// Update the cache with the new data and file's current modification time
	c.data[feedName] = &CachedData{
		Feed:    &feedData,
		LastMod: fileInfo.ModTime(),
	}

	return &feedData, nil
}

// Invalidate removes a feed from the in-memory cache.
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

		// Extract feed name from the full AT-URI
		parts := strings.Split(feedParam, "/")
		feedName := parts[len(parts)-1]

		filePath := filepath.Join(cache.feedsDir, feedName, feedFileName)
		fileInfo, err := os.Stat(filePath)
		if err != nil {
			// If file is not found (and initial refresh hasn't completed yet), return 404
			http.Error(w, "feed file not found", http.StatusNotFound)
			return
		}

		// Handle If-Modified-Since header for 304 response
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
			// GetFeed handles file not found errors, but if an internal error
			// like JSON decoding occurs, it returns 500.
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Pagination logic
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

		// Set the cursor for the next page
		if end < len(feed.Feed) {
			response["cursor"] = feed.Feed[end-1].Post
		}

		// Set response headers
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
			// Check if the mandatory DID file exists in the directory
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
    
	// Start the periodic refresh loop in a goroutine immediately.
	// The Start function will execute the first refresh asynchronously.
	go refresher.Start(ctx, refreshInterval) 
	log.Println("Starting periodic feed refresh and session management in background.")

	http.HandleFunc("/xrpc/app.bsky.feed.getFeedSkeleton", feedHandler(cache, refreshInterval))
	log.Printf("Starting bsky feed-daemon on port %d...", *port)
	// Start HTTP server immediately, relying on feedHandler to check file existence.
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", *port), nil))
}
