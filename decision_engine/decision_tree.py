import json

WEIGHTS = {
    "cvss": 0.35,
    "epss": 0.25,
    "kev": 0.25,
    "fix": 0.15
}

def calculate_risk_score(cvss, epss_score, in_kev, fix_available):
    score = 0
    score += (cvss / 10) * WEIGHTS["cvss"] * 100      # CVSS is 0–10
    score += epss_score * WEIGHTS["epss"] * 100       # EPSS is 0–1
    score += (1 if in_kev else 0) * WEIGHTS["kev"] * 100
    score += (1 if fix_available else 0) * WEIGHTS["fix"] * 100
    return round(score, 2)

def map_score_to_decision(score):
    if score >= 85:
        return "Act ASAP", "Critical"
    elif score >= 65:
        return "Act", "High"
    elif score >= 45:
        return "Track", "Medium"
    else:
        return "Defer", "Low"

def classify_cve(cve):
    cvss = cve.get("cvss", 0)
    epss = cve.get("epss_score", 0)
    kev = cve.get("in_kev", False)
    fix = cve.get("fix_available", False)

    risk_score = calculate_risk_score(cvss, epss, kev, fix)
    decision, risk_band = map_score_to_decision(risk_score)

    justification = []
    if kev:
        justification.append("Listed in CISA KEV (known exploit)")
    if fix:
        justification.append("Fix available")
    if epss > 0.7:
        justification.append(f"High EPSS score ({epss})")
    if cvss >= 7.0:
        justification.append(f"High CVSS score ({cvss})")

    return {
        **cve,
        "risk_score": risk_score,
        "risk_band": risk_band,
        "decision": decision,
        "justification": "; ".join(justification) or "No strong risk indicators",
        "actionable": fix
    }

def classify_all(input_file, output_file):
    with open(input_file, "r") as f:
        cves = json.load(f)

    prioritized = [classify_cve(cve) for cve in cves]

    with open(output_file, "w") as f:
        json.dump(prioritized, f, indent=2)

    print(f"✅ Processed {len(prioritized)} CVEs using updated decision logic → {output_file}")

if __name__ == "__main__":
    classify_all("enrichment/enriched_cves.json", "decision_engine/prioritized_cves.json")