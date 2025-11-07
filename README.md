# 🔍 ReconPy — Lightweight Reconnaissance Tool (Team Alpha)

**ReconPy** is a Python-based lightweight reconnaissance tool built by **Team Alpha (Interns)**.  
It automates common surface discovery tasks such as DNS record lookup, subdomain enumeration, port scanning, TLS certificate inspection, and HTTP metadata collection — all in a single, easy-to-use command-line interface.

---

## ⚠️ Disclaimer
This tool is designed for **educational and authorized security testing only**.  
Do **not** use ReconPy to scan systems without explicit permission.

---

## 🧠 About ReconPy
ReconPy is a practical, lightweight, and modular reconnaissance utility created by **Team Alpha** to assist interns and students in learning ethical hacking and network reconnaissance.  
It integrates multiple scanning functions into one workflow:

- DNS Enumeration (A, AAAA, NS, MX, TXT)
- Subdomain Discovery (built-in + custom wordlist)
- Port Scanning (default/common/custom ports)
- TLS Certificate Inspection (subject, issuer, SANs, validity)
- HTTP(S) Title & Header Fetching (robots.txt check)
- JSON, TXT & HTML Report Generation

Reports are stored locally and can be easily shared or converted using the `make_report.py` helper script.

---

## 🚀 Features
| Category | Description |
|-----------|--------------|
| **DNS Enumeration** | Collects A, AAAA, NS, MX, TXT records |
| **Subdomain Finder** | Resolves subdomains via built-in or custom list |
| **Port Scanner** | Checks for open/closed TCP ports |
| **TLS Inspector** | Fetches certificate details (subject, issuer, SAN) |
| **HTTP Info** | Gets page title, headers & robots.txt |
| **Fingerprint** | Generates hash fingerprint of title + server header |
| **Output Formats** | JSON (detailed) & terminal table summary |
| **Report Generator** | Converts JSON → HTML & TXT automatically |

---

## ⚙️ Installation
### Prerequisites
- Python 3.8 or higher  
- Optional libraries for extended features:
  ```bash
  python3 -m pip install --user requests dnspython
git clone https://github.com/malkaenoor/reconpy.git
cd reconpy
python3 recon_final.py -t example.com
python3 recon_final.py -t example.com -p 1-1024
python3 recon_final.py -t example.com -w subdomains.txt
python3 recon_final.py -t example.com --no-dns --no-sub --no-http
python3 recon_final.py -t example.com --repo-url https://github.com/malkaenoor/reconpy
reconpy/
├── recon_final.py          # main recon tool
├── make_report.py          # report generator
├── examples/               # example reports
├── README.md               # documentation
├── CONTRIBUTORS.md          # team details
└── LICENSE                 # MIT license
Developers — Team Alpha
| Name            | Role                    | GitHub                                          |
| --------------- | ----------------------- | ----------------------------------------------- |
| **Ayesha Noor** | Lead Intern / Developer | [malkaenoor](https://github.com/malkaenoor)     |
| **Bilal Nasir** | Co-Developer / Research | [bilalnasir15](https://github.com/bilalnasir15) |
