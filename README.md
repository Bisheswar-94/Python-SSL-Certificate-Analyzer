# Python SSL Certificate Analyzer

A Python cybersecurity project that fetches and analyzes SSL/TLS certificates from websites.

## Features

- Fetch SSL certificates
- Analyze issuer details
- Check certificate expiry
- Detect expired certificates
- Detect expiring certificates
- TLS version detection
- Save reports to TXT and JSON

---

## Project Structure

```bash
Python-SSL-Certificate-Analyzer/
│
├── ssl_analyzer.py
├── targets.txt
├── requirements.txt
├── README.md
│
├── results/
│   ├── report.txt
│   └── report.json
```

---

## Installation

Clone the repository:

```bash
git clone https://github.com/yourusername/Python-SSL-Certificate-Analyzer.git
cd Python-SSL-Certificate-Analyzer
```

---

## Usage

Run the tool:

```bash
python ssl_analyzer.py
```

---

## Example Output

```bash
[+] Scanning google.com ...

Issued To      : *.google.com
Issued By      : Google Trust Services
Expiry         : Sep 02 23:59:59 2026 GMT
Remaining Days : 57
TLS Version    : TLSv1.3
Status         : VALID
```

---

## Output Files

### TXT Report
Stored in:

```bash
results/report.txt
```

### JSON Report
Stored in:

```bash
results/report.json
```

---

## Future Improvements

- Multi-threaded scanning
- Weak cipher detection
- TLS vulnerability checks
- CSV export
- Colored terminal output
- Command-line arguments
- Certificate chain analysis

---

## Educational Purpose

This project is created for educational and cybersecurity learning purposes only.
