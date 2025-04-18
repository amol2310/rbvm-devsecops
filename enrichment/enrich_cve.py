import requests
import json
import time
import os

CACHE_DIR = "cache"
os.makedirs(CACHE_DIR, exist_ok=True)

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API_BASE = "https://api.first.org/data/v1/epss?cve="

def log(message):
    print(f"[LOG] {message}")

def cache_get(cache_file):
    path = os.path.join(CACHE_DIR, cache_file)
    if os.path.exists(path):
        log(f"Cache hit: {cache_file}")
        with open(path, "r") as f:
            return json.load(f)
    else:
        log(f"Cache miss: {cache_file}")
    return None

def cache_set(cache_file, data):
    path = os.path.join(CACHE_DIR, cache_file)
    with open(path, "w") as f:
        json.dump(data, f)
    log(f"Cache saved: {cache_file}")

def get_epss_score(cve_id):
    cache_file = f"epss_{cve_id}.json"
    cached = cache_get(cache_file)
    if cached is not None:
        return cached.get("epss", 0.0), cached.get("available", False)

    try:
        response = requests.get(EPSS_API_BASE + cve_id)
        if response.status_code == 200:
            data = response.json()
            if data["data"]:
                score = float(data["data"][0]["epss"])
                cache_set(cache_file, {"epss": score, "available": True})
                return score, True
    except Exception as e:
        log(f"[EPSS] Error for {cve_id}: {e}")
    cache_set(cache_file, {"epss": 0.0, "available": False})
    return 0.0, False

def load_kev_list():
    CACHE_DIR = "cache"
    cache_file = os.path.join(CACHE_DIR, "kev_list.json")
    cached = cache_get(cache_file)
    if os.path.exists(cache_file):
        print(f"[LOG] Loading KEV list from {cache_file}")
        with open(cache_file, "r") as f:
            return set(json.load(f))

    try:
        r = requests.get(CISA_KEV_URL)
        if r.status_code == 200:
            kev_data = r.json()
            kev_set = [item["cveID"] for item in kev_data.get("vulnerabilities", [])]
            os.makedirs(CACHE_DIR, exist_ok=True)
            with open(cache_file, "w") as f:
                json.dump(kev_set, f)
            return set(kev_set)
    except Exception as e:
        print(f"[ERROR] Could not fetch KEV list: {e}")
    return set()

def enrich_cves(input_file, output_file):
    with open(input_file, 'r') as infile:
        cve_list = json.load(infile)

    kev_set = load_kev_list()

    enriched_cves = []
    for cve in cve_list:
        cve_id = cve.get("cve_id")
        log(f"Enriching CVE: {cve_id}")

        epss_cache_file = f"epss_{cve_id}.json"
        epss_cached = os.path.exists(os.path.join(CACHE_DIR, epss_cache_file))
        epss_score, epss_available = get_epss_score(cve_id)

        in_kev = cve_id in kev_set
        fix_available = cve.get("fixed_version", "unknown") != "unknown"
        cvss_score = cve.get("cvss", 0.0)

        enriched_cves.append({
            **cve,
            "epss_score": epss_score,
            "epss_score_available": epss_available,
            "cvss": cvss_score,
            "in_kev": in_kev,
            "fix_available": fix_available
        })

        if not epss_cached:
            time.sleep(0.5)

    with open(output_file, 'w') as outfile:
        json.dump(enriched_cves, outfile, indent=2)
    log(f"Enriched {len(enriched_cves)} CVEs written to {output_file}")

if __name__ == "__main__":
    enrich_cves("ingestion/normalized_cves.json", "enrichment/enriched_cves.json")