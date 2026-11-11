import json
import time
import urllib.request
from pathlib import Path

DATA = Path(__file__).resolve().parent.parent / "data"
API = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="


def fetch_one(cve_id):
    with urllib.request.urlopen(API + cve_id, timeout=30) as resp:
        item = json.load(resp)["vulnerabilities"][0]["cve"]
    metrics = item.get("metrics", {})
    score = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics:
            score = metrics[key][0]["cvssData"]["baseScore"]
            break
    summary = next((d["value"] for d in item["descriptions"] if d["lang"] == "en"), "")
    return {"cvss": score, "summary": summary[:200]}


def main():
    cve_map = json.loads((DATA / "cve_map.json").read_text())
    cache_file = DATA / "cvss_cache.json"
    cache = json.loads(cache_file.read_text()) if cache_file.exists() else {}

    ids = sorted({c for lst in cve_map.values() for c in lst})
    for cve_id in ids:
        if cve_id in cache:
            print(f"cached  {cve_id}")
            continue
        try:
            cache[cve_id] = fetch_one(cve_id)
            print(f"fetched {cve_id}  CVSS {cache[cve_id]['cvss']}")
        except Exception as e:
            print(f"failed  {cve_id}: {e}")
        cache_file.write_text(json.dumps(cache, indent=2))
        time.sleep(7)  # NVD allows about 5 requests per 30 seconds without a key


if __name__ == "__main__":
    main()
