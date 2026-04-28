package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"sync"

	"github.com/spf13/pflag"
	"github.com/rix4uni/ffufscan/banner"
)

// DuplicateTracker tracks unique fingerprints per domain
type DuplicateTracker struct {
	mu         sync.RWMutex
	fingerprints map[string]map[string]bool // domain -> fingerprint -> seen
}

func NewDuplicateTracker() *DuplicateTracker {
	return &DuplicateTracker{
		fingerprints: make(map[string]map[string]bool),
	}
}

func (dt *DuplicateTracker) IsDuplicate(domain, fingerprint string) bool {
	dt.mu.RLock()
	if domainMap, exists := dt.fingerprints[domain]; exists {
		if seen := domainMap[fingerprint]; seen {
			dt.mu.RUnlock()
			return true
		}
	}
	dt.mu.RUnlock()
	return false
}

func (dt *DuplicateTracker) MarkSeen(domain, fingerprint string) {
	dt.mu.Lock()
	if dt.fingerprints[domain] == nil {
		dt.fingerprints[domain] = make(map[string]bool)
	}
	dt.fingerprints[domain][fingerprint] = true
	dt.mu.Unlock()
}

// FfufResult represents a single ffuf JSON output line
type FfufResult struct {
	URL      string  `json:"url"`
	Status   int     `json:"status"`
	Length   int     `json:"length"`
	Words    int     `json:"words"`
	Lines    int     `json:"lines"`
	Duration int64   `json:"duration"`
}

func main() {
	wordlist := pflag.String("wordlist", "", "Path to wordlist (required)")
	ffufArgs := pflag.String("ffuf-args", "", "Additional ffuf flags (e.g., '-mc 200,301 -t 100')")
	filterDups := pflag.Bool("filter", false, "Filter duplicate responses (same Size, Words, Lines per domain)")
	recursive := pflag.Bool("recursive", false, "Enable recursive directory enumeration")
	recursionDepth := pflag.Int("recursion-depth", 0, "Maximum recursion depth (0 = no recursion)")
	fuzzCode := pflag.String("fuzzcode", "", "Status codes to trigger recursion (e.g., '301,302')")
	silent := pflag.Bool("silent", false, "Silent mode.")
	version := pflag.Bool("version", false, "Print the version of the tool and exit.")
	pflag.Parse()

	if *version {
		banner.PrintBanner()
		banner.PrintVersion()
		return
	}

	if !*silent {
		banner.PrintBanner()
	}

	tracker := NewDuplicateTracker()

	// Parse fuzzcode if provided
	var targetCodes map[int]bool
	if *fuzzCode != "" {
		targetCodes = parseStatusCodes(*fuzzCode)
	}

	if *wordlist == "" {
		fmt.Fprintln(os.Stderr, "Error: -w flag is required (wordlist path)")
		pflag.Usage()
		os.Exit(1)
	}

	// Check if wordlist exists
	if _, err := os.Stat(*wordlist); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Error: wordlist file not found: %s\n", *wordlist)
		os.Exit(1)
	}

	// Read URLs from stdin
	var urls []string
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		url := strings.TrimSpace(scanner.Text())
		if url != "" {
			urls = append(urls, url)
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading stdin: %v\n", err)
		os.Exit(1)
	}

	if len(urls) == 0 {
		fmt.Fprintln(os.Stderr, "Error: no URLs provided via stdin")
		os.Exit(1)
	}

	// Parse additional ffuf args
	var extraArgs []string
	if *ffufArgs != "" {
		extraArgs = parseArgs(*ffufArgs)
	}

	// Worker pool with 5 concurrent workers
	const numWorkers = 5
	urlChan := make(chan string, len(urls))
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for targetURL := range urlChan {
				runFfuf(targetURL, *wordlist, extraArgs, *filterDups, tracker, 1)
			}
		}()
	}

	// Send URLs to workers
	for _, url := range urls {
		urlChan <- url
	}
	close(urlChan)

	// Wait for all workers to finish
	wg.Wait()

	// Handle recursion if enabled
	if *recursive && *recursionDepth > 0 {
		runRecursiveScans(urls, *wordlist, extraArgs, *recursionDepth, targetCodes, tracker, 2, *filterDups)
	}
}

func parseArgs(args string) []string {
	var result []string
	var current strings.Builder
	inQuote := false
	quoteChar := rune(0)

	for _, r := range args {
		switch r {
		case '"', '\'':
			if !inQuote {
				inQuote = true
				quoteChar = r
			} else if quoteChar == r {
				inQuote = false
				quoteChar = 0
			} else {
				current.WriteRune(r)
			}
		case ' ', '\t':
			if inQuote {
				current.WriteRune(r)
			} else {
				if current.Len() > 0 {
					result = append(result, current.String())
					current.Reset()
				}
			}
		default:
			current.WriteRune(r)
		}
	}

	if current.Len() > 0 {
		result = append(result, current.String())
	}

	return result
}

func parseStatusCodes(codes string) map[int]bool {
	result := make(map[int]bool)
	for _, code := range strings.Split(codes, ",") {
		code = strings.TrimSpace(code)
		if num, err := strconv.Atoi(code); err == nil {
			result[num] = true
		}
	}
	return result
}

func runRecursiveScans(initialURLs []string, wordlist string, extraArgs []string, maxDepth int, targetCodes map[int]bool, tracker *DuplicateTracker, startDepth int, filterDups bool) {
	// Track all discovered directories per domain to avoid re-scanning
	scannedDirs := make(map[string]map[string]bool) // domain -> directory URL -> scanned

	// Build initial set of base URLs
	currentURLs := make([]string, len(initialURLs))
	copy(currentURLs, initialURLs)

	for depth := 0; depth < maxDepth; depth++ {
		currentDepth := startDepth + depth
		var nextURLs []string

		// Create a new tracker for this depth level to enable per-depth deduplication
		depthTracker := NewDuplicateTracker()

		// Collect results for this depth level
		var mu sync.Mutex
		var results []FfufResult

		// Run ffuf on current URLs
		const numWorkers = 5
		urlChan := make(chan string, len(currentURLs))
		var wg sync.WaitGroup

		for i := 0; i < numWorkers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for targetURL := range urlChan {
					r := runFfufCollect(targetURL, wordlist, extraArgs, depthTracker, currentDepth, filterDups)
					mu.Lock()
					results = append(results, r...)
					mu.Unlock()
				}
			}()
		}

		for _, u := range currentURLs {
			urlChan <- u
		}
		close(urlChan)
		wg.Wait()

		// Print results and find directories for next level
		for _, res := range results {
			// Print the result with colors and depth prefix if verbose
			printResult(res, currentDepth)

			// Check if this should trigger recursion
			if targetCodes != nil && !targetCodes[res.Status] {
				continue
			}

			// Check if it's a directory (no dot in last segment)
			if isDirectory(res.URL) {
				parsed, err := url.Parse(res.URL)
				if err != nil {
					continue
				}
				domain := parsed.Host

				// Initialize map for this domain if needed
				if scannedDirs[domain] == nil {
					scannedDirs[domain] = make(map[string]bool)
				}

				// Skip if already scanned
				if scannedDirs[domain][res.URL] {
					continue
				}
				scannedDirs[domain][res.URL] = true

				// Add to next level URLs
				nextURLs = append(nextURLs, res.URL)
			}
		}

		// If no new directories found, stop
		if len(nextURLs) == 0 {
			break
		}

		currentURLs = nextURLs
	}
}

func isDirectory(urlStr string) bool {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	// Get the last path segment
	lastSegment := path.Base(parsed.Path)
	// A directory has no dot in its name
	return !strings.Contains(lastSegment, ".")
}

func printResult(result FfufResult, depth int) {
	durationMs := result.Duration / 1000000

	// Determine status color based on HTTP status code
	var statusColor string
	switch {
	case result.Status >= 200 && result.Status < 300:
		statusColor = "\033[32m" // Green for 2xx
	case result.Status >= 300 && result.Status < 400:
		statusColor = "\033[33m" // Yellow for 3xx
	case result.Status >= 400 && result.Status < 500:
		statusColor = "\033[31m" // Red for 4xx
	case result.Status >= 500:
		statusColor = "\033[35m" // Magenta for 5xx
	default:
		statusColor = "\033[0m" // Reset
	}

	reset := "\033[0m"
	blue := "\033[34m"
	cyan := "\033[36m"
	green := "\033[32m"

	fmt.Printf("%s[DEPTH-%d]%s %s%s%s %s[Status: %s%d%s, Size: %s%d%s, Words: %s%d%s, Lines: %s%d%s, Duration: %s%dms%s]%s\n",
		green, depth, reset,
		cyan, result.URL, reset,
		blue, statusColor, result.Status, blue,
		reset, result.Length, blue,
		reset, result.Words, blue,
		reset, result.Lines, blue,
		reset, durationMs, blue,
		reset)
}

func runFfufCollect(targetURL, wordlist string, extraArgs []string, tracker *DuplicateTracker, depth int, filterDups bool) []FfufResult {
	var results []FfufResult

	// Extract domain for filtering
	var domain string
	parsedURL, err := url.Parse(targetURL)
	if err == nil {
		domain = parsedURL.Host
	}

	// Ensure URL ends with FUZZ
	fuzzURL := targetURL
	if !strings.HasSuffix(fuzzURL, "FUZZ") {
		if !strings.HasSuffix(fuzzURL, "/") {
			fuzzURL += "/"
		}
		fuzzURL += "FUZZ"
	}

	// Build base ffuf command
	args := []string{
		"-s",
		"-u", fuzzURL,
		"-w", wordlist,
		"-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
		"-maxtime-job", "60",
		"-json",
	}

	// Add extra args
	args = append(args, extraArgs...)

	cmd := exec.Command("ffuf", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return results
	}

	if err := cmd.Start(); err != nil {
		return results
	}

	// Parse JSON output line by line
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var result FfufResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			continue
		}

		// Check for duplicates if filtering is enabled
		if filterDups && domain != "" {
			fingerprint := fmt.Sprintf("%d:%d:%d", result.Length, result.Words, result.Lines)
			if tracker.IsDuplicate(domain, fingerprint) {
				continue
			}
			tracker.MarkSeen(domain, fingerprint)
		}

		results = append(results, result)
		printResult(result, depth)
	}

	cmd.Wait()
	return results
}

func runFfuf(targetURL, wordlist string, extraArgs []string, filterDups bool, tracker *DuplicateTracker, depth int) []FfufResult {
	var results []FfufResult

	// Extract domain for filtering
	var domain string
	if filterDups {
		parsedURL, err := url.Parse(targetURL)
		if err == nil {
			domain = parsedURL.Host
		}
	}
	// Ensure URL ends with FUZZ
	fuzzURL := targetURL
	if !strings.HasSuffix(fuzzURL, "FUZZ") {
		if !strings.HasSuffix(fuzzURL, "/") {
			fuzzURL += "/"
		}
		fuzzURL += "FUZZ"
	}

	// Build base ffuf command
	args := []string{
		"-s",
		"-u", fuzzURL,
		"-w", wordlist,
		"-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
		"-maxtime-job", "60",
		"-json",
	}

	// Add extra args
	args = append(args, extraArgs...)

	cmd := exec.Command("ffuf", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return results
	}

	if err := cmd.Start(); err != nil {
		return results
	}

	// Parse JSON output line by line
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var result FfufResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			// Skip non-JSON lines (errors, etc.)
			continue
		}

		// Check for duplicates if filtering is enabled
		if filterDups && domain != "" {
			fingerprint := fmt.Sprintf("%d:%d:%d", result.Length, result.Words, result.Lines)
			if tracker.IsDuplicate(domain, fingerprint) {
				continue
			}
			tracker.MarkSeen(domain, fingerprint)
		}

		results = append(results, result)
		printResult(result, depth)
	}

	cmd.Wait()
	return results
}
