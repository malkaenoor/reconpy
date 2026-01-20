🔍 ReconPy — Lightweight Reconnaissance Tool

Team lambda (Interns)

ReconPy is a Python-based lightweight yet powerful reconnaissance framework .
It automates essential surface-level reconnaissance tasks such as DNS enumeration, subdomain discovery, port scanning, HTTP security analysis, and automated screenshots — all through a single, clean command-line interface.

⚠️ Disclaimer

This tool is intended strictly for educational purposes and authorized security testing.
Do NOT use ReconPy against systems without explicit permission.
The authors take no responsibility for misuse.

🧠 About ReconPy

ReconPy is a modular, beginner-friendly, and extensible recon tool designed to help interns and students understand real-world reconnaissance workflows used in ethical hacking and penetration testing.

It combines multiple reconnaissance techniques into a single pipeline and produces professional, shareable reports.

.

🧩 Core Capabilities

ReconPy integrates the following modules:

DNS Enumeration
Basic Subdomain Enumeration

Discovers common subdomains using built-in wordlists

Advanced Subdomain Enumeration

Passive + brute-force discovery using:

VirusTotal API
Shodan API
DNS brute-force & permutations

Port Scanning
Scans default, common, or custom TCP ports

HTTP Enumeration

HTTP Security Headers Analysis
Detects presence and absence of critical headers:

Automated Website Screenshots
Captures full-page screenshots of HTTP/HTTPS services for visual reconnaissance

Professional Reporting
Generates structured JSON reports for easy sharing and post-processing

🚀 Features Overview
Category                 |      Description
DNS Enumeration	Collects | A, AAAA, NS, MX, TXT records
Subdomain Finder	       |Basic + advanced (API-based & brute-force)
Port Scanner	           |Detects open & closed TCP ports
HTTP Enumeration         |	Status codes, titles, server headers
Security Headers	       |Identifies missing HTTP security headers
Screenshots              |	Automated visual recon of websites
WHOIS Lookup	           |Domain registration details
Output	                 |Terminal tables + JSON reports

## ⚙️ Installation

### 📌 Prerequisites
- Python 3.8 or higher
- Git
- Linux / Kali Linux recommended

---
### 📥 Clone Repository

```bash
git clone https://github.com/malkaenoor/reconpy.git

cd reconpy

python3 -m venv venv

source venv/bin/activate

pip install requests dnspython

pip install python-dotenv

pip install python-dotenv shodan vt-py dnsgen

python3 recon_final.py -t example.com --advanced-subdomains --http-headers --whois

python3 recon_final.py -t example.com --screenshots

🔹 View Screenshot (GUI)
bash
Copy code
xdg-open screenshots/example.com.png

🔹 View Screenshot (Terminal)
bash
Copy code
sudo apt install feh -y
feh screenshots/example.com.png

python3 recon_final.py -t example.com -p 80,443,8080

python3 recon_final.py -t example.com -p 1-1000

example.com_recon.json
