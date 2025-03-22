# cve_fetcher.py

import requests
from datetime import datetime, timedelta

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def get_latest_cves(limit=10):
    headers = {
        "apiKey": API_KEY
    }

    now = datetime.utcnow()
    yesterday = now - timedelta(days=1)

    params = {
        "startIndex": 0,
        "resultsPerPage": limit,
        "pubStartDate": yesterday.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
    }

    try:
        response = requests.get(NVD_API_URL, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()

        results = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            descriptions = cve.get("descriptions", [])
            summary = next((d["value"] for d in descriptions if d["lang"] == "en"), None)

            # Extract CVSS score
            metrics = cve.get("metrics", {})
            score = None
            if "cvssMetricV31" in metrics:
                score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
            elif "cvssMetricV30" in metrics:
                score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
            elif "cvssMetricV2" in metrics:
                score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

            # Filter by score > 7.0
            if score is not None and score <= 7.0:
                continue  # Skip lower severity

            # PoC link (GitHub)
            references = cve.get("references", [])
            poc = next((r["url"] for r in references if "github.com" in r.get("url", "")), None)

            if cve_id and summary:
                results.append({
                    "id": cve_id,
                    "summary": summary,
                    "poc": poc,
                    "score": score
                })

        return results

    except Exception as e:
        print(f"❌ Error fetching CVEs from NVD: {e}")
        return []
