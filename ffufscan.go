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

	"github.com/rix4uni/ffufscan/banner"
	"github.com/spf13/pflag"
)

// DuplicateTracker tracks unique fingerprints per domain
type DuplicateTracker struct {
	mu           sync.RWMutex
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
	URL      string `json:"url"`
	Status   int    `json:"status"`
	Length   int    `json:"length"`
	Words    int    `json:"words"`
	Lines    int    `json:"lines"`
	Duration int64  `json:"duration"`
}

func main() {
	wordlist := pflag.String("wordlist", "", "Path to wordlist (required)")
	ffufcmd := pflag.String("ffufcmd", "", "Additional ffuf flags (e.g., '-mc 200,301 -t 100')")
	noFilter := pflag.Bool("no-filter", false, "Disable duplicate responses filter (same Size, Words, Lines per domain)")
	depth := pflag.Int("depth", 0, "Maximum directory recursion depth (0 = no recursion)")
	fuzzCode := pflag.String("fuzzcode", "", "Status codes to trigger recursion (e.g., '301,302')")
	silent := pflag.Bool("silent", false, "Silent mode.")
	version := pflag.Bool("version", false, "Print the version of the tool and exit.")
	pflag.Parse()

	filterDups := !*noFilter

	if *version {
		banner.PrintBanner()
		banner.PrintVersion()
		return
	}

	if !*silent {
		banner.PrintBanner()
	}

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
		u := strings.TrimSpace(scanner.Text())
		if u != "" {
			urls = append(urls, u)
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
	if *ffufcmd != "" {
		extraArgs = parseArgs(*ffufcmd)
	}

	// Determine max depth
	maxDepth := 1
	if *depth > 0 {
		maxDepth = *depth
	}

	// Track scanned directories per domain to avoid duplicate scans
	scannedDirs := make(map[string]map[string]bool)
	for _, u := range urls {
		parsed, err := url.Parse(u)
		if err == nil {
			if scannedDirs[parsed.Host] == nil {
				scannedDirs[parsed.Host] = make(map[string]bool)
			}
			scannedDirs[parsed.Host][strings.TrimRight(u, "/")] = true
			scannedDirs[parsed.Host][strings.TrimRight(u, "/")+"/"] = true
		}
	}

	const numWorkers = 5
	currentURLs := urls

	for currentDepth := 1; currentDepth <= maxDepth; currentDepth++ {
		var (
			depthTracker *DuplicateTracker
			mu           sync.Mutex
			results      []FfufResult
			wg           sync.WaitGroup
		)

		if filterDups {
			depthTracker = NewDuplicateTracker()
		}

		numW := numWorkers
		if len(currentURLs) < numW {
			numW = len(currentURLs)
		}

		urlChan := make(chan string, len(currentURLs))

		for i := 0; i < numW; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for targetURL := range urlChan {
					r := runFfuf(targetURL, *wordlist, extraArgs, depthTracker, filterDups, currentDepth)
					if currentDepth < maxDepth {
						mu.Lock()
						results = append(results, r...)
						mu.Unlock()
					}
				}
			}()
		}

		for _, u := range currentURLs {
			urlChan <- u
		}
		close(urlChan)
		wg.Wait()

		if currentDepth >= maxDepth {
			break
		}

		// Find discovered directories for the next depth level
		var nextURLs []string
		for _, res := range results {
			if targetCodes != nil && !targetCodes[res.Status] {
				continue
			}

			if isDirectory(res.URL) {
				parsed, err := url.Parse(res.URL)
				if err != nil {
					continue
				}
				domain := parsed.Host

				if scannedDirs[domain] == nil {
					scannedDirs[domain] = make(map[string]bool)
				}

				trimmedURL := strings.TrimRight(res.URL, "/")
				if scannedDirs[domain][trimmedURL] || scannedDirs[domain][trimmedURL+"/"] {
					continue
				}
				scannedDirs[domain][trimmedURL] = true
				scannedDirs[domain][trimmedURL+"/"] = true

				nextURLs = append(nextURLs, res.URL)
			}
		}

		if len(nextURLs) == 0 {
			break
		}

		currentURLs = nextURLs
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

func isDirectory(urlStr string) bool {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	cleanPath := path.Clean(parsed.Path)
	if cleanPath == "/" || cleanPath == "." {
		return false
	}
	lastSegment := path.Base(cleanPath)
	return lastSegment != "" && lastSegment != "/" && lastSegment != "." && !strings.Contains(lastSegment, ".")
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

func runFfuf(targetURL, wordlist string, extraArgs []string, tracker *DuplicateTracker, filterDups bool, depth int) []FfufResult {
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
		if filterDups && tracker != nil && domain != "" {
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
