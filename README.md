# AutoReconLite

AutoReconLite is a lightweight, modular Python recon tool.

## Features
- DNS subdomain enumeration (candidate-based DNS queries)
- Threaded scan of common ports: 21,22,23,25,53,80,110,143,443,3306,8080
- HTTP security header checks
- Basic directory brute forcing (wordlist)
- Basic findings: missing headers, potential exposed admin panels
- Formatted terminal report

## Install
```bash
pip install -r requirements.txt
```

## Usage
```bash
python autoreconlite.py example.com
```

More options:
```bash
python autoreconlite.py example.com --threads 300 --dir-threads 80 --timeout 2 --http-timeout 6 --wordlist data/wordlist.txt
```

## Disclaimer
Use only on systems you own or where you have explicit permission to test.
