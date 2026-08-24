## ffufscan

A concurrent ffuf wrapper for fuzzing piped URLs with recursive scanning and automatic duplicate filtering.

### Prerequisites
```
go install github.com/ffuf/ffuf/v2@latest
```

## Installation
```
go install github.com/rix4uni/ffufscan@latest
```

## Download prebuilt binaries
```
wget https://github.com/rix4uni/ffufscan/releases/download/v0.0.2/ffufscan-linux-amd64-0.0.2.tgz
tar -xvzf ffufscan-linux-amd64-0.0.2.tgz
rm -rf ffufscan-linux-amd64-0.0.2.tgz
mv ffufscan ~/go/bin/ffufscan
```
Or download [binary release](https://github.com/rix4uni/ffufscan/releases) for your platform.

## Compile from source
```
git clone --depth 1 github.com/rix4uni/ffufscan.git
cd ffufscan; go install
```

## Usage
```
Usage of ffufscan:
      --depth int         Maximum directory recursion depth (0 = no recursion)
      --ffufcmd string    Additional ffuf flags (e.g., '-mc 200,301 -t 100')
      --fuzzcode string   Status codes to trigger recursion (e.g., '301,302')
      --no-filter         Disable duplicate responses filter (same Size, Words, Lines per domain)
      --silent            Silent mode.
      --version           Print the version of the tool and exit.
      --wordlist string   Path to wordlist (required)
```

## Usage Examples
### Single URL
```console
echo "https://example.com" | ffufscan --wordlist wordlist.txt
```

### Multiple URLs
```console
cat subs.txt | ffufscan --wordlist wordlist.txt
```

### Custom ffuf command
```console
cat subs.txt | ffufscan --wordlist wordlist.txt --ffufcmd "-mc 200,301 -t 100"
```

## Output Format
```console
[DEPTH-1] https://example.com/images [Status: 301, Size: 274, Words: 15, Lines: 8, Duration: 158ms]
[DEPTH-1] https://example.com/downloads [Status: 200, Size: 4060, Words: 602, Lines: 95, Duration: 160ms]
[DEPTH-1] https://example.com/.htaccess [Status: 403, Size: 239, Words: 15, Lines: 8, Duration: 153ms]
[DEPTH-2] https://example.com/images/favicon.ico [Status: 200, Size: 5430, Words: 16, Lines: 14, Duration: 163ms]
```
