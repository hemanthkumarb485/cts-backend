import requests

url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
headers = {"apiKey": "4648c095-6cf1-4115-886b-ed81ed335960"}
params = {"cveId": "CVE-2021-44228"}

print(f"Querying NVD API for CVE-2021-44228 with new apiKey...")
try:
    r = requests.get(url, headers=headers, params=params, timeout=10)
    print("Status Code:", r.status_code)
    if r.status_code == 200:
        data = r.json()
        vulns = data.get("vulnerabilities", [])
        if vulns:
            cve_data = vulns[0].get("cve", {})
            print("Successfully retrieved CVE details! ID:", cve_data.get("id"))
            desc = next((d["value"] for d in cve_data.get("descriptions", []) if d.get("lang") == "en"), "")
            print("Description Snippet:", desc[:100] + "...")
        else:
            print("No vulnerabilities found in response.")
    else:
        print("Response Text:", r.text)
except Exception as e:
    print("Failed to query NVD API:", e)
