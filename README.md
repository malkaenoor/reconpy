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
> ⚠️ Use only on authorized targets.
---
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


🐍 Create Virtual Environment (Recommended)
bash
Copy code
python3 -m venv venv
source venv/bin/activate

📦 Install Dependencies
bash
Copy code
pip install -r requirements.txt
If requirements.txt is missing, install manually:

bash
Copy code
pip install requests dnspython

🚀 Usage
🔹 Basic Recon Scan
bash
Copy code
python3 recon_final.py -t example.com
🔹 Custom Port Range
bash
Copy code
python3 recon_final.py -t example.com -p 1-1024

🔹 Subdomain Enumeration with Wordlist
bash
Copy code
python3 recon_final.py -t example.com -w subdomains.txt
🔹 Disable Specific Modules
bash
Copy code
python3 recon_final.py -t example.com --no-dns --no-sub --no-http

📊 Output
Automatic JSON report generation:
example.com_recon.json

Developers — Team Lambda by ITSOERA
