#!/usr/bin/env python3
"""
ReconPy - Professional Recon Tool
Author: malkaenoor
Description:
A modular reconnaissance framework supporting DNS enumeration,
advanced subdomain discovery, port scanning, banner grabbing,
technology detection, and professional report generation.
"""

# ===================== STANDARD LIBRARIES ===================== #
from advanced_subdomains import *
import os
import argparse
import socket
import json
import ssl
from http_headers import check_http_security_headers
from datetime import datetime
from urllib.parse import urljoin
from html import unescape
from screenshots import take_screenshot

# ---------------- OPTIONAL LIBS ----------------
try:
    import dns.resolver
    DNSPY = True
except:
    DNSPY = False

try:
    import requests
    REQUESTS = True
except:
    REQUESTS = False

try:
    import whois
    WHOIS = True
except:
    WHOIS = False

# ---------------- DEFAULTS ----------------
DEFAULT_SUBS = ["www","mail","ftp","dev","test","stage","api","admin","blog","vpn"]
DEFAULT_PORTS = [21,22,25,53,80,110,143,443,445,3389,8080,8443]

# ---------------- UTILS ----------------
def now():
    return datetime.utcnow().isoformat()+"Z"

def banner():
    print("="*90)
    print(" ReconPy | Lightweight Recon Framework")
    print("="*90)

def table(headers, rows):
    widths = [len(h) for h in headers]
    for r in rows:
        for i,c in enumerate(r):
            widths[i] = max(widths[i], len(str(c)))

    sep = "+" + "+".join("-"*(w+2) for w in widths) + "+"
    print(sep)
    print("| " + " | ".join(headers[i].ljust(widths[i]) for i in range(len(headers))) + " |")
    print(sep)
    for r in rows:
        print("| " + " | ".join(str(r[i]).ljust(widths[i]) for i in range(len(r))) + " |")
    print(sep)

# ---------------- MODULES ----------------
def dns_lookup(domain):
    print("\n[+] DNS Enumeration")
    data = {"A":[],"AAAA":[],"NS":[],"MX":[],"TXT":[]}
    if DNSPY:
        for r in data:
            try:
                ans = dns.resolver.resolve(domain, r, lifetime=4)
                data[r] = [str(a).rstrip('.') for a in ans]
            except:
                pass
    rows = []
    for k,v in data.items():
        rows.append([k, ", ".join(v) if v else "-"])
    table(["Type","Value"], rows)
    return data

def whois_lookup(domain):
    print("\n[+] WHOIS Lookup")
    if not WHOIS:
        print("WHOIS library not installed")
        return {}
    try:
        w = whois.whois(domain)
        rows = [
            ["Registrar", w.registrar],
            ["Created", w.creation_date],
            ["Updated", w.updated_date],
            ["Expiry", w.expiration_date],
            ["Name Servers", ", ".join(w.name_servers) if w.name_servers else "-"]
        ]
        table(["Field","Value"], rows)
        return {
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "updated_date": str(w.updated_date),
            "expiration_date": str(w.expiration_date),
            "name_servers": list(w.name_servers) if w.name_servers else []
        }
    except Exception as e:
        print("WHOIS failed:", e)
        return {}

def subdomain_enum(domain):
    print("\n[+] Subdomain Enumeration (Basic)")
    rows = []
    found = []
    for s in DEFAULT_SUBS:
        sub = f"{s}.{domain}"
        try:
            ip = socket.gethostbyname(sub)
            rows.append([sub, ip])
            found.append({"subdomain": sub, "ip": ip})
        except:
            pass
    if rows:
        table(["Subdomain","IP"], rows)
    else:
        print("No subdomains found")
    return found

def advanced_subdomain_enum(domain):
    print("\n[+] Advanced Subdomain Enumeration (Passive + Brute)")
    results = set()
    rows = []

    try:
        for s in virustotal_enum(domain):
            results.add(s)
    except:
        pass

    try:
        for s in shodan_enum(domain):
            results.add(s)
    except:
        pass

    try:
        for s in bruteforce_enum(domain):
            results.add(s)
    except:
        pass

    for sub in sorted(results):
        try:
            ip = socket.gethostbyname(sub)
        except:
            ip = "-"
        rows.append([sub, ip])

    if rows:
        table(["Subdomain","IP"], rows)
    else:
        print("No advanced subdomains found")

    return [{"subdomain": r[0], "ip": r[1]} for r in rows]

def port_scan(domain, ports):
    print("\n[+] Port Scanning")
    rows = []
    result = {}
    for p in ports:
        try:
            s = socket.socket()
            s.settimeout(1)
            s.connect((domain, p))
            rows.append([p,"OPEN"])
            result[p] = True
            s.close()
        except:
            rows.append([p,"CLOSED"])
            result[p] = False
    table(["Port","State"], rows)
    return result

def http_enum(domain):
    print("\n[+] HTTP Enumeration")
    data = {}
    if not REQUESTS:
        print("requests module not installed")
        return {}
    for scheme in ["http","https"]:
        try:
            url = f"{scheme}://{domain}"
            r = requests.get(url, timeout=5, headers={"User-Agent":"ReconPy"})
            title = "-"
            if "<title>" in r.text.lower():
                title = unescape(r.text.split("<title>")[1].split("</title>")[0])
            data[scheme] = {
                "url": url,
                "status": r.status_code,
                "title": title,
                "server": r.headers.get("Server")
            }
        except:
            data[scheme] = {}
    rows = []
    for k,v in data.items():
        rows.append([k, v.get("status"), v.get("title"), v.get("server")])
    table(["Proto","Status","Title","Server"], rows)
    return data

# ---------------- CLI ----------------
def parse_ports(p):
    if not p:
        return DEFAULT_PORTS
    out = []
    for x in p.split(","):
        if "-" in x:
            a,b = x.split("-")
            out.extend(range(int(a), int(b)+1))
        else:
            out.append(int(x))
    return sorted(set(out))
#________________main__________________
def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("-p", "--ports")
    parser.add_argument("--whois", action="store_true")
    parser.add_argument("--advanced-subdomains", action="store_true")
    parser.add_argument("--http-headers", action="store_true")
    parser.add_argument("--screenshots",action="store_true",
    help="Capture automated screenshots of target"
)

    args = parser.parse_args()
    ports = parse_ports(args.ports)
    run(
    args.target,
    ports,
    args.whois,
    args.advanced_subdomains,
    args.http_headers,
    args.screenshots
)

#__________________run___________________
def run(target, ports, do_whois, advanced, do_headers, do_screenshots):
    banner()

    report = {
        "target": target,
        "timestamp": now()
    }

    report["dns"] = dns_lookup(target)

    if do_whois:
        report["whois"] = whois_lookup(target)

    report["subdomains"] = subdomain_enum(target)

    if advanced:
        report["advanced_subdomains"] = advanced_subdomain_enum(target)

    report["ports"] = port_scan(target, ports)
    report["http"] = http_enum(target)

    # ---------------- HTTP SECURITY HEADERS ----------------
    if do_headers:
        print("\n[+] HTTP Security Headers")
        report["http_security_headers"] = check_http_security_headers(target)

    # ---------------- AUTOMATED SCREENSHOTS ----------------
    if do_screenshots:
        print("\n[+] Automated Screenshots")
        screenshots = []

        for scheme in ["http", "https"]:
            url = f"{scheme}://{target}"
            path = take_screenshot(url)
            screenshots.append({
                "url": url,
                "file": path
            })

        report["screenshots"] = screenshots

    fname = f"{target}_recon.json"
    with open(fname, "w") as f:
        json.dump(report, f, indent=2)

    print("\n[✓] Recon Complete")
    print(f"[✓] Report saved → {fname}")
    print("=" * 90)


if __name__ == "__main__":
    main()
