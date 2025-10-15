import os
import sys
import requests
import shodan
from dotenv import load_dotenv
load_dotenv()

SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
if not SHODAN_API_KEY:
    print("ERROR: Please set SHODAN_API_KEY environment variable and try again.")
    sys.exit(1)

TARGET = "www.yoursite.com"
DNS_RESOLVE_URL = "https://api.shodan.io/dns/resolve"

def resolve_hostname_to_ip(hostname: str, api_key: str):
    params = {"hostnames": hostname, "key": api_key}
    print(f"[debug] Resolving hostname {hostname} via Shodan DNS API...")
    resp = requests.get(DNS_RESOLVE_URL, params=params, timeout=10)
    # raise for HTTP errors so we see the reason
    resp.raise_for_status()
    data = resp.json()
    print(f"[debug] DNS resolve raw response: {data}")
    return data.get(hostname)  # returns None if missing

def print_host_info(api: shodan.Shodan, ip: str):
    print(f"[debug] Querying Shodan host info for IP: {ip}")
    host = api.host(ip)
    print("=== Host summary ===")
    print(f"IP: {host.get('ip_str', ip)}")
    print(f"Organization: {host.get('org', 'n/a')}")
    print(f"Operating System: {host.get('os', 'n/a')}")
    print("--------------------")

    services = host.get("data", [])
    if not services:
        print("No services/banners found for this host.")
    else:
        for svc in services:
            port = svc.get("port", "n/a")
            banner = svc.get("data", "")
            banner_preview = banner if len(banner) < 800 else banner[:800] + "...(truncated)"
            print(f"Port: {port}")
            print(f"Banner preview:\n{banner_preview}\n")

    vulns = host.get("vulns")
    if not vulns:
        print("No vulnerabilities recorded by Shodan for this host.")
    else:
        print("Vulnerabilities:")
        for vuln in vulns:
            cve = vuln.lstrip("!")
            print(f" - {cve}")
            try:
                exploits = api.exploits.search(cve)
                matches = exploits.get("matches", [])
                if matches:
                    for m in matches:
                        desc = m.get("description", "").strip()
                        print(f"    * {desc[:300]}{'...' if len(desc) > 300 else ''}")
                else:
                    print("    (no exploit matches found)")
            except shodan.APIError as e:
                print(f"    (exploit search error: {e})")

def main():
    api = shodan.Shodan(SHODAN_API_KEY)

    try:
        ip = resolve_hostname_to_ip(TARGET, SHODAN_API_KEY)
    except requests.HTTPError as e:
        print(f"HTTP error while resolving hostname: {e}")
        print("Response content (if any):")
        try:
            print(e.response.text)
        except Exception:
            pass
        sys.exit(1)
    except Exception as e:
        print("Unexpected error while resolving hostname:", e)
        sys.exit(1)

    if not ip:
        print(f"Could not resolve {TARGET} to an IP via Shodan DNS API. The response didn't include the hostname key.")
        print("Possible reasons: invalid API key, endpoint not allowed for your plan, or domain has no public IP.")
        sys.exit(1)

    try:
        print_host_info(api, ip)
    except shodan.APIError as e:
        print("Shodan API error while fetching host info:", e)
        sys.exit(1)
    except Exception as e:
        print("Unexpected error while fetching host info:", e)
        raise

if __name__ == "__main__":
    main()
