import os
import requests
from datetime import datetime, timedelta

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY = os.getenv("NVD_API_KEY")

def get_latest_cves(limit=10, min_score=7.0, user_filter=None):
    headers = {"apiKey": API_KEY}
    now = datetime.utcnow()
    yesterday = now - timedelta(days=1)

    params = {
        "startIndex": 0,
        "resultsPerPage": limit,
        "pubStartDate": yesterday.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
    }

    try:
        response = requests.get(NVD_API_URL, headers=headers, params=params, timeout=15)
        response.raise_for_status()
        data = response.json()

        results = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            summary = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), None)

            metrics = cve.get("metrics", {})
            score = None
            for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if key in metrics:
                    score = metrics[key][0].get("cvssData", {}).get("baseScore")
                    break

            if score is None or score < min_score:
                continue

            references = cve.get("references", [])
            poc = next((r["url"] for r in references if "github.com" in r.get("url", "")), None)

            if not cve_id or not summary:
                continue

            if user_filter:
                text = summary.lower()
                vendor_match = any(v in text for v in user_filter.get("vendor", []))
                keyword_match = any(k in text for k in user_filter.get("keyword", []))
                cwe_match = any(cwe in summary for cwe in user_filter.get("cwe", []))

                if not (vendor_match or keyword_match or cwe_match):
                    continue

            results.append({"id": cve_id, "summary": summary, "score": score, "poc": poc})

        return results
    except Exception as e:
        print(f"❌ Error fetching CVEs: {e}")
        return []
