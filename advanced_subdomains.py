import os
import dns.resolver
from dotenv import load_dotenv
import shodan
import vt
from dnsgen import dnsgen

load_dotenv()

# ================= PASSIVE ENUM ================= #

def shodan_enum(domain):
    subs = set()
    try:
        api_key = os.getenv("SHODAN_API_KEY")
        if not api_key:
            return []

        api = shodan.Shodan(api_key)
        data = api.dns.domain_info(domain)

        for s in data.get("subdomains", []):
            subs.add(f"{s}.{domain}")
    except:
        pass

    return list(subs)


def virustotal_enum(domain):
    subs = set()
    try:
        api_key = os.getenv("VT_API_KEY")
        if not api_key:
            return []

        client = vt.Client(api_key)
        for obj in client.iterator(f"/domains/{domain}/subdomains"):
            subs.add(obj.id)
        client.close()
    except:
        pass

    return list(subs)


# ================= BRUTE FORCE ================= #

def bruteforce_enum(domain, wordlist="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"):
    found = set()
    try:
        with open(wordlist, "r", errors="ignore") as f:
            for word in f:
                sub = f"{word.strip()}.{domain}"
                try:
                    dns.resolver.resolve(sub, "A")
                    found.add(sub)
                except:
                    pass
    except:
        pass

    return list(found)


# ================= PERMUTATIONS ================= #

def permutations_enum(subdomains):
    results = set()
    try:
        for d in dnsgen(subdomains):
            results.add(d)
    except:
        pass

    return list(results)


# ================= MASTER MERGE ================= #

def advanced_enum(domain):
    """
    Full advanced enumeration:
    - Shodan (passive)
    - VirusTotal (passive)
    - Bruteforce (active)
    - Permutations
    """

    shodan_subs = shodan_enum(domain)
    vt_subs = virustotal_enum(domain)
    brute_subs = bruteforce_enum(domain)

    base = set(shodan_subs + vt_subs + brute_subs)
    permuted = permutations_enum(base)

    final = set(base) | set(permuted)
    return sorted(final)
