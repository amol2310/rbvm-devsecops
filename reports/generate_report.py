import json
import csv

def generate_report(input_file, output_file):
    with open(input_file) as f:
        prioritized = json.load(f)

    with open(output_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["CVE ID", "Package", "Severity", "CVSS", "Risk Score", "Decision"])
        for cve in prioritized:
            writer.writerow([
                cve["cve_id"],
                cve["package"],
                cve["severity"],
                cve["cvss"],
                cve["risk_score"],
                cve["decision"]
            ])
    print(f"CSV report saved to {output_file}")

if __name__ == "__main__":
    generate_report("decision_engine/prioritized_cves.json", "reports/prioritized_cves.csv")