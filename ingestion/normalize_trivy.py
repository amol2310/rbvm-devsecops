import json

def normalize_trivy(input_file, output_file):
    with open(input_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    normalized = []
    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            cvss_data = vuln.get("CVSS", {})
            cvss_score = 0.0
            if "nvd" in cvss_data:
                cvss_score = cvss_data["nvd"].get("V3Score", 0.0) or cvss_data["nvd"].get("V2Score", 0.0)
            elif len(cvss_data) > 0:
                cvss_score = list(cvss_data.values())[0].get("V3Score", 0.0)

            normalized.append({
                "cve_id": vuln["VulnerabilityID"],
                "package": vuln["PkgName"],
                "severity": vuln["Severity"],
                "fixed_version": vuln.get("FixedVersion", "unknown"),
                "cvss": cvss_score
            })

    with open(output_file, "w") as f:
        json.dump(normalized, f, indent=2)
    print(f"Normalized {len(normalized)} CVEs to {output_file}")

if __name__ == "__main__":
    normalize_trivy("scanners/sample_output/trivy_output.json", "ingestion/normalized_cves.json")