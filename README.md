## ffufscan

A Go CLI tool that wraps `ffuf` for directory/file fuzzing with piped URL input and colored output.

## Features

- **Piped URL input** - Read URLs from stdin
- **Concurrent scanning** - Run up to 5 parallel ffuf scans
- **Colored output** - Status codes color-coded like ffuf:
  - 🟢 Green (2xx) - Success
  - 🟡 Yellow (3xx) - Redirects
  - 🔴 Red (4xx) - Client errors
  - 🟣 Magenta (5xx) - Server errors
- **Custom ffuf flags** - Pass additional arguments via `--ffuf-args`
- **Filter duplicates** - Hide responses with identical Size/Words/Lines per domain using `--filter`
- **Recursive scanning** - Automatically enumerate discovered directories using `--recursive` and `--recursion-depth`
- **Status code filtering** - Filter recursive targets by status code using `--fuzzcode`
- **Depth tracking** - All output shows `[DEPTH-N]` prefix indicating recursion level

### Prerequisites

- [Go](https://golang.org/) 1.21 or later
- [ffuf](https://github.com/ffuf/ffuf) installed and available in PATH

## Installation
```
go install github.com/rix4uni/ffufscan@latest
```

## Download prebuilt binaries
```
wget https://github.com/rix4uni/ffufscan/releases/download/v0.0.1/ffufscan-linux-amd64-0.0.1.tgz
tar -xvzf ffufscan-linux-amd64-0.0.1.tgz
rm -rf ffufscan-linux-amd64-0.0.1.tgz
mv ffufscan ~/go/bin/ffufscan
```
Or download [binary release](https://github.com/rix4uni/ffufscan/releases) for your platform.

## Compile from source
```
git clone --depth 1 github.com/rix4uni/ffufscan.git
cd ffufscan; go install
```

## Usage

### Basic usage with single URL
```console
echo "https://sagadb.org" | ffufscan --wordlist advanced_sensitive_wordlist.txt
```

### Multiple URLs from file
```console
cat subs.txt | ffufscan --wordlist wordlist.txt
```

### With additional ffuf flags
```console
cat subs.txt | ffufscan --wordlist wordlist.txt --ffuf-args "-mc 200,301 -t 100"
```

## Flags

| Flag | Description | Required |
|------|-------------|----------|
| `--wordlist` | Path to wordlist file | Yes |
| `--ffuf-args` | Additional ffuf flags (e.g., `--mc 200,301 -t 50`) | No |
| `--filter` | Filter duplicate responses per domain (same Size, Words, Lines) | No |
| `--recursive` | Enable recursive directory enumeration | No |
| `--recursion-depth` | Maximum recursion depth (default: 0, no recursion) | No |
| `--fuzzcode` | Status codes to trigger recursion (e.g., `301,302`) | No |

## Default ffuf flags

The tool automatically uses these ffuf flags:
- `-s` - Silent mode (no banner)
- `-u URL/FUZZ` - Target URL with FUZZ placeholder
- `-w wordlist` - Wordlist path
- `-H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)"` - Custom User-Agent
- `-maxtime-job 60` - 60 second timeout per job
- `-json` - JSON output for parsing

## Output Format

```console
[DEPTH-1] https://sagadb.org/images [Status: 301, Size: 274, Words: 15, Lines: 8, Duration: 158ms]
[DEPTH-1] https://sagadb.org/downloads [Status: 200, Size: 4060, Words: 602, Lines: 95, Duration: 160ms]
[DEPTH-1] https://sagadb.org/.htaccess [Status: 403, Size: 239, Words: 15, Lines: 8, Duration: 153ms]
[DEPTH-2] https://sagadb.org/images/favicon.ico [Status: 200, Size: 5430, Words: 16, Lines: 14, Duration: 163ms]
```

## Examples

### Scan a single target
```console
echo "https://example.com" | ffufscan --wordlist /usr/share/wordlists/dirb/common.txt
```

### Scan multiple subdomains with custom threads
```console
cat subdomains.txt | ffufscan --wordlist wordlist.txt --ffuf-args "-t 50"
```

### Filter specific status codes
```console
echo "https://target.com" | ffufscan --wordlist wordlist.txt --ffuf-args "-mc 200,301,302"
```

### Filter duplicate responses
Hide pages that return the same response (useful for reducing noise from 404 pages):
```console
echo "https://sagadb.org" | ffufscan --wordlist wordlist.txt --filter
```

With `--filter`, only the first occurrence of each unique response (by Size:Words:Lines) per domain is shown. Multiple domains are tracked independently. When using recursive scanning, deduplication is applied separately within each depth level (DEPTH-1, DEPTH-2, etc.).

### Recursive directory enumeration
Automatically scan discovered directories:
```console
# Basic recursive (depth 1)
echo "https://sagadb.org" | ffufscan --wordlist wordlist.txt --recursive --recursion-depth 1

# Recursive 2 levels deep
echo "https://sagadb.org" | ffufscan --wordlist wordlist.txt --recursive --recursion-depth 2

# Recursive only on 301 redirects
echo "https://sagadb.org" | ffufscan --wordlist wordlist.txt --recursive --recursion-depth 1 --fuzzcode "301"

# Recursive on 301 and 302
echo "https://sagadb.org" | ffufscan --wordlist wordlist.txt --recursive --recursion-depth 1 --fuzzcode "301,302"
```

The `--recursive` flag enables automatic enumeration of discovered directories (URLs without a dot in the last path segment). The `--recursion-depth` controls how many levels deep to go. The `--fuzzcode` flag filters which status codes trigger recursion.

All output includes a `[DEPTH-N]` prefix showing which recursion level discovered each result:
- `DEPTH-1`: Initial scan (base URLs from stdin)
- `DEPTH-2`: First recursive level
- `DEPTH-3+`: Deeper recursive levels
