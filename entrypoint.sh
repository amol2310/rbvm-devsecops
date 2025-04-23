#!/bin/bash

set -e

if [ -z "$1" ]; then
  echo "Please provide a Docker image to scan"
  exit 1
fi
TARGET_IMAGE="$1"

echo "------Scanning Docker image: $TARGET_IMAGE--------"
sh scanners/run_trivy.sh "$TARGET_IMAGE"

echo "-------Normalizing...--------"
python ingestion/normalize_trivy.py

echo "--------Enriching...---------"
python enrichment/enrich_cve.py

echo "--------Prioritizing...---------"
python decision_engine/decision_tree.py

#python reports/generate_report.py
mkdir -p scanner_output/target
mv ingestion/normalized_cves.json enrichment/enriched_cves.json decision_engine/prioritized_cves.json scanner_output/target/

echo "Launching Streamlit dashboard..."
# Run Streamlit in background and redirect output
nohup streamlit run dashboard/streamlit_app.py --server.port 8501 --server.address 0.0.0.0 > /dev/null 2>&1 &

echo "Check the dashboard at http://localhost:8501"

ACT_ASAP_COUNT=$(jq '[.[] | select(.decision=="Act ASAP")] | length' target/prioritized_cves.json)
ACT_COUNT=$(jq '[.[] | select(.decision=="Act")] | length' target/prioritized_cves.json)

echo "CVE Prioritization complete."
echo "Act ASAP CVEs: $ACT_ASAP_COUNT"
echo "Act CVEs: $ACT_COUNT"

# Fail build if any Act ASAP or Act CVEs exist
if [ "$ACT_ASAP_COUNT" -gt 0 ] || [ "$ACT_COUNT" -gt 0 ]; then
  echo "High-risk vulnerabilities detected (Act ASAP or Act). Failing build..."
  exit 1
else
  echo "No high-risk vulnerabilities. Build may proceed."
  exit 0
fi
