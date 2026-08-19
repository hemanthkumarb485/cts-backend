import requests

url = "https://api.first.org/data/v1/epss"
cves = ["CVE-2000-0071"]

print(f"Querying {url} for {cves}...")
try:
    r = requests.get(url, params={"cve": ",".join(cves)}, timeout=10)
    print("Status Code:", r.status_code)
    import pprint
    pprint.pprint(r.json())
except Exception as e:
    print("Failed to query EPSS API:", e)
