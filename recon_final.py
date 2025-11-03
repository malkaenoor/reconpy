#!/usr/bin/env python3
"""
ReconPy - lightweight recon module for red team interns
Features:
 - DNS records (uses dnspython if available)
 - Subdomain brute (small builtin list + optional file)
 - TCP connect port scanning (configurable ports)
 - HTTP fetch: title, headers, robots.txt
 - TLS cert inspection
 - Simple fingerprint (hash of title+server header)
 - JSON output
Author: ChatGPT (example)
Use responsibly (authorized targets only).

This variant adds a terminal-friendly tabular pretty-printing helper using only
Python standard library (no extra deps) so it won't introduce import errors.
It also embeds a safe GitHub repository helper: two CLI flags --repo-url and
--write-repo-file which only print instructions and optionally save an
informational JSON file. The script will never run git commands automatically.
"""
import argparse
import socket
import ssl
import sys
import json
import hashlib
import time
from datetime import datetime
from urllib.parse import urljoin
from html import unescape
import os

# Try to import optional libs
try:
    import dns.resolver
    DNSPY = True
except Exception:
    DNSPY = False

try:
    import requests
    REQUESTS = True
except Exception:
    REQUESTS = False

# Default small subdomain wordlist (augmentable)
DEFAULT_SUBS = [
    "www","dev","test","stage","api","mail","webmail","beta","admin","portal",
    "ftp","m","shop","vpn","secure","smtp","owa","blog","support"
]

# Default common ports
DEFAULT_PORTS = [21,22,23,25,53,80,110,135,139,143,443,445,3389,5900,8080,8443]

# ---------------------------
# Utilities
# ---------------------------
def now_ts():
    return datetime.utcnow().isoformat() + "Z"

def resolve_dns(domain):
    out = {"A": [], "AAAA": [], "NS": [], "MX": [], "TXT": []}
    if DNSPY:
        resolver = dns.resolver.Resolver()
        for rec in ["A","AAAA","NS","MX","TXT"]:
            try:
                answers = resolver.resolve(domain, rec, lifetime=5)
                for r in answers:
                    out[rec].append(str(r).rstrip('.'))
            except Exception:
                pass
    else:
        # Basic A lookup fallback
        try:
            adds = socket.getaddrinfo(domain, None)
            for a in adds:
                ip = a[4][0]
                if ":" in ip:
                    if ip not in out["AAAA"]:
                        out["AAAA"].append(ip)
                else:
                    if ip not in out["A"]:
                        out["A"].append(ip)
        except Exception:
            pass
    return out

def tcp_connect(host, port, timeout=1.5):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.close()
        return True
    except Exception:
        return False

def get_cert(host, port=443, timeout=3):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                # normalize some fields
                issuer = dict(x[0] for x in cert.get('issuer', ()))
                subject = dict(x[0] for x in cert.get('subject', ()))
                san = cert.get('subjectAltName', ())
                return {
                    "subject": subject,
                    "issuer": issuer,
                    "notBefore": cert.get('notBefore'),
                    "notAfter": cert.get('notAfter'),
                    "SAN": [s[1] for s in san if s[0].lower()=='dns']
                }
    except Exception:
        return None

def fetch_http(host, port=80, path='/', timeout=5, use_https=False):
    url = ("https" if use_https else "http") + "://" + host
    if port not in (80,443):
        url = url.replace("://", f":{port}://")
    url = urljoin(url, path.lstrip("/"))
    result = {"url": url, "status": None, "headers": {}, "title": None, "robots": None}
    if not REQUESTS:
        # minimal HTTP via socket (only GET headers and first chunk)
        try:
            scheme = "https" if use_https else "http"
            if use_https:
                ctx = ssl.create_default_context()
            sock = socket.create_connection((host, port), timeout=timeout)
            if use_https:
                sock = ctx.wrap_socket(sock, server_hostname=host)
            req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: ReconPy/1.0\r\nConnection: close\r\n\r\n"
            sock.send(req.encode())
            data = b""
            chunk = sock.recv(4096)
            data += chunk
            sock.close()
            head_body = data.split(b"\r\n\r\n",1)
            head = head_body[0].decode(errors='ignore')
            result["headers"] = dict([line.split(":",1) for line in head.split("\r\n")[1:] if ":" in line])
            result["status"] = head.split("\r\n")[0]
            if len(head_body)>1:
                body = head_body[1].decode(errors='ignore')
                # simple title extraction
                if "<title" in body.lower():
                    start = body.lower().find("<title")
                    start = body.lower().find(">", start)+1
                    end = body.lower().find("</title>", start)
                    if end>start:
                        result["title"] = unescape(body[start:end].strip())
        except Exception:
            pass
        return result
    else:
        try:
            r = requests.get(url, timeout=timeout, allow_redirects=True, headers={"User-Agent":"ReconPy/1.0"})
            result["status"] = r.status_code
            result["headers"] = {k:v for k,v in r.headers.items()}
            text = r.text
            if "<title" in text.lower():
                start = text.lower().find("<title")
                start = text.lower().find(">", start)+1
                end = text.lower().find("</title>", start)
                if end>start:
                    result["title"] = unescape(text[start:end].strip())
            # robots
            try:
                rr = requests.get(urljoin(url, "/robots.txt"), timeout=3, headers={"User-Agent":"ReconPy/1.0"})
                result["robots"] = rr.status_code
            except Exception:
                result["robots"] = None
        except Exception:
            pass
        return result

def fingerprint_str(title, headers):
    key = (title or "") + "|" + (headers.get("Server","") or headers.get("server","") or "")
    h = hashlib.sha256(key.encode()).hexdigest()[:12]
    return h

# ---------------------------
# High-level tasks
# ---------------------------
def find_subdomains(domain, wordlist=None, resolve=True):
    found = []
    words = wordlist if wordlist else DEFAULT_SUBS
    for w in words:
        sub = f"{w}.{domain}"
        if not resolve:
            found.append(sub)
            continue
        try:
            # simple A resolve
            ips = []
            if DNSPY:
                answers = dns.resolver.resolve(sub, "A", lifetime=2)
                ips = [str(a) for a in answers]
            else:
                try:
                    res = socket.gethostbyname_ex(sub)
                    ips = res[2]
                except Exception:
                    ips = []
            if ips:
                found.append({"subdomain": sub, "ips": ips})
        except Exception:
            pass
    return found

def port_scan_for_host(host, ports, timeout=0.8):
    results = {}
    # prefer IPs: try to resolve host to IP for scanning
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        ip = host
    for p in ports:
        ok = tcp_connect(ip, int(p), timeout=timeout)
        results[p] = ok
    return results

# ---------------------------
# Tabular printing helper (standard library only)
# ---------------------------

def _stringify(cell):
    if cell is None:
        return ""
    if isinstance(cell, (list, tuple, set)):
        return ", ".join(str(x) for x in cell)
    return str(cell)

def format_table(headers, rows, padding=1):
    """Return a string representing a simple ASCII table.
    headers: list of column names
    rows: list of row iterables (same length as headers)
    Uses only standard library so no extra deps required.
    """
    # stringify all cells
    srows = [[_stringify(c) for c in row] for row in rows]
    cols = list(range(len(headers)))
    widths = []
    for i in cols:
        col_cells = [str(headers[i])] + [r[i] if i < len(r) else '' for r in srows]
        widths.append(max(len(x) for x in col_cells))
    sep = "+" + "+".join(["-"*(w+2*padding) for w in widths]) + "+\n"
    # header
    out = sep
    header_cells = "|" + "|".join([" "+headers[i].ljust(widths[i])+" " for i in cols]) + "|\n"
    out += header_cells
    out += sep
    # rows
    for r in srows:
        cells = "|" + "|".join([" "+(r[i] if i < len(r) else '').ljust(widths[i])+" " for i in cols]) + "|\n"
        out += cells
    out += sep
    return out

# ---------------------------
# GitHub repo helper (safe)
# ---------------------------

def print_git_instructions(repo_url, repo_name=None):
    """
    Print safe, copy-paste git commands the user can run to add a remote
    and push without changing anything automatically.
    """
    print("\n[GitHub Repository Helper]")
    print(f"Repository URL: {repo_url}")
    if repo_name:
        print(f"Suggested repo name: {repo_name}")
    print()
    print("If you want to add this repository as a remote for the current folder, run:")
    print("  # initialize git repo if not already (this won't overwrite your files)")
    print("  [ -d .git ] || git init")
    print("  git remote add origin " + repo_url)
    print("  git branch -M main            # rename branch to main (optional)")
    print("  git add reconpy.py README.md .gitignore   # stage files you want")
    print("  git commit -m \"Add reconpy tool\"         # commit locally")
    print("  git push -u origin main                    # push to GitHub (manual)")
    print("\nNote: run these commands yourself — the script will not run them for you.\n")


def save_repo_metadata(repo_url, path='repo_info.json'):
    """
    Save repo metadata to a local JSON file.
    This will only be done if the user explicitly requests it via --write-repo-file.
    """
    meta = {
        "repo_url": repo_url,
        "saved_at": datetime.utcnow().isoformat() + "Z",
        "note": "This file is informational only. Script does not auto-push to GitHub."
    }
    try:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(meta, f, indent=2)
        print(f"[+] Repo metadata written to {path}")
    except Exception as e:
        print(f"[!] Failed to write repo metadata: {e}")

# ---------------------------
# CLI and orchestrator
# ---------------------------
def run_recon(target, ports, sub_wordlist_file=None, do_sub=True, do_dns=True, do_http=True, outjson=True):
    out = {"target": target, "timestamp": now_ts(), "dns": {}, "subdomains": [], "ports": {}, "http": {}, "cert": None, "fingerprint": None}
    # DNS
    if do_dns:
        out["dns"] = resolve_dns(target)
    # Subdomains
    wordlist = None
    if sub_wordlist_file:
        try:
            with open(sub_wordlist_file,'r') as f:
                wordlist = [l.strip() for l in f if l.strip()]
        except Exception:
            wordlist = None
    if do_sub:
        out["subdomains"] = find_subdomains(target, wordlist, resolve=True)
    # Port scan
    out["ports"] = port_scan_for_host(target, ports)
    # TLS cert (443)
    cert = get_cert(target, 443)
    out["cert"] = cert
    # HTTP (80 and 443)
    if do_http:
        http80 = fetch_http(target, 80, "/", use_https=False)
        http443 = fetch_http(target, 443, "/", use_https=True)
        # choose best result (prefer https)
        best = http443 if http443.get("status") else http80
        out["http"] = {"http": http80, "https": http443, "best": best}
        out["fingerprint"] = fingerprint_str(best.get("title"), best.get("headers") or {})
    # Save JSON
    if outjson:
        fname = f"{target.replace('/','_')}_recon.json"
        with open(fname,'w') as f:
            json.dump(out, f, indent=2)
        print(f"[+] Saved JSON to {fname}")
    return out


def pretty_print(out):
    # Top header
    print("="*80)
    print(f"Recon for {out['target']}  @ {out['timestamp']}")
    print("="*80)

    # DNS table
    dns = out.get('dns', {}) or {}
    dns_rows = []
    for k in ['A','AAAA','NS','MX','TXT']:
        vals = dns.get(k) or []
        dns_rows.append([k, ", ".join(vals)])
    print("-- DNS Records --")
    print(format_table(['Type','Value'], dns_rows))

    # Subdomains table
    subs = out.get('subdomains', []) or []
    sub_rows = []
    for s in subs:
        if isinstance(s, dict):
            sub_rows.append([s.get('subdomain'), _stringify(s.get('ips'))])
        else:
            sub_rows.append([s, ''])
    if sub_rows:
        print("-- Subdomains Found --")
        print(format_table(['Subdomain','IPs'], sub_rows))
    else:
        print("-- Subdomains Found --\nNo subdomains discovered.\n")

    # Ports table (show port and state)
    ports = out.get('ports', {}) or {}
    port_rows = [[str(p), ('open' if ok else 'closed')] for p,ok in sorted(ports.items(), key=lambda x: int(x[0]))]
    if port_rows:
        print("-- Port Scan --")
        print(format_table(['Port','State'], port_rows))
    else:
        print("-- Port Scan --\nNo ports scanned.\n")

    # TLS Cert
    print("-- TLS Certificate (443) --")
    c = out.get('cert')
    if c:
        cert_rows = [
            ['Subject', _stringify(c.get('subject'))],
            ['Issuer', _stringify(c.get('issuer'))],
            ['Valid From', c.get('notBefore')],
            ['Valid To', c.get('notAfter')],
            ['SANs', _stringify(c.get('SAN'))]
        ]
        print(format_table(['Field','Value'], cert_rows))
    else:
        print("No certificate found or failed to retrieve.\n")

    # HTTP best
    print("-- HTTP (best) --")
    b = (out.get('http',{}) or {}).get('best',{}) or {}
    http_rows = [
        ['URL', b.get('url')],
        ['Status', b.get('status')],
        ['Title', b.get('title')],
        ['Server Header', b.get('headers',{}).get('Server') or b.get('headers',{}).get('server')],
        ['robots.txt', b.get('robots')]
    ]
    print(format_table(['Field','Value'], http_rows))

    # Fingerprint
    print("-- Fingerprint --")
    print(out.get('fingerprint'))
    print("="*80)

# ---------------------------
# Entry point
# ---------------------------
def parse_ports(s):
    if not s:
        return DEFAULT_PORTS
    parts = s.split(",")
    out = []
    for p in parts:
        p = p.strip()
        if "-" in p:
            a,b = p.split("-",1)
            out.extend(list(range(int(a), int(b)+1)))
        else:
            out.append(int(p))
    return sorted(set(out))

def main():
    parser = argparse.ArgumentParser(description="ReconPy - lightweight recon tool")
    parser.add_argument("-t","--target", required=True, help="target domain (example.com)")
    parser.add_argument("-p","--ports", help="comma list or range of ports (e.g. 21,22,80-90). Default common ports")
    parser.add_argument("-w","--wordlist", help="subdomain wordlist file (one per line)")
    parser.add_argument("--no-dns", action="store_true", help="skip DNS lookups")
    parser.add_argument("--no-sub", action="store_true", help="skip subdomain discovery")
    parser.add_argument("--no-http", action="store_true", help="skip HTTP fetch")
    # <-- Added flags for GitHub repo helper (safe: passive behavior)
    parser.add_argument("--repo-url", help="(optional) GitHub repo URL to print helper commands for (no automatic push)")
    parser.add_argument("--write-repo-file", action="store_true", help="If set with --repo-url, save repo metadata to repo_info.json")

    args = parser.parse_args()

    ports = parse_ports(args.ports) if args.ports else DEFAULT_PORTS
    out = run_recon(
        target=args.target,
        ports=ports,
        sub_wordlist_file=args.wordlist,
        do_sub=not args.no_sub,
        do_dns=not args.no_dns,
        do_http=not args.no_http,
        outjson=True
    )

    pretty_print(out)

    # If user provided --repo-url, print safe git instructions and optionally save metadata
    if getattr(args, 'repo_url', None):
        # derive repo name for display
        repo_name = args.repo_url.rstrip('/').split('/')[-1]
        print_git_instructions(args.repo_url, repo_name=repo_name)
        if getattr(args, 'write_repo_file', False) or getattr(args, 'write-repo-file', False) or args.write_repo_file:
            # default filename repo_info.json
            save_repo_metadata(args.repo_url, path='repo_info.json')

if __name__ == "__main__":
    main()
