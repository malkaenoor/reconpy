"""
HTTP Security Headers Analysis Module
Author: malkaenoor

This module inspects HTTP/HTTPS responses to identify
missing or present security-related headers.
"""

import requests

# Industry-standard security headers to check
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy"
]


def check_http_security_headers(domain, timeout=5):
    """
    Checks HTTP and HTTPS endpoints of a domain
    for common security headers.

    Returns:
        List of dictionaries with results per URL
    """

    results = []

    for scheme in ["http", "https"]:
        url = f"{scheme}://{domain}"

        try:
            response = requests.get(
                url,
                timeout=timeout,
                headers={"User-Agent": "ReconPy"}
            )

            present = []
            missing = []

            for header in SECURITY_HEADERS:
                if header in response.headers:
                    present.append(header)
                else:
                    missing.append(header)

            results.append({
                "url": url,
                "status_code": response.status_code,
                "present_headers": present,
                "missing_headers": missing
            })

        except requests.RequestException:
            # Endpoint not reachable
            results.append({
                "url": url,
                "status_code": None,
                "present_headers": [],
                "missing_headers": SECURITY_HEADERS.copy()
            })

    return results
