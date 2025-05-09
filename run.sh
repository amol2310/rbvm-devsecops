#!/bin/bash

set -e

if [ -z "$1" ]; then
  echo "Please provide a Docker image to scan"
  exit 1
fi
TARGET_IMAGE="$1"

echo "------Scanning Docker image: $TARGET_IMAGE--------"
sh scanners/run_trivy.sh $TARGET_IMAGE

echo "-------Normalizing...--------"
python ingestion/normalize_trivy.py

echo "--------Enriching...---------"
python enrichment/enrich_cve.py

echo "--------Prioritizing...---------"
python decision_engine/decision_tree.py

#python reports/generate_report.py
mkdir target
mv ingestion/normalized_cves.json enrichment/enriched_cves.json decision_engine/prioritized_cves.json target/

echo "Launching Streamlit dashboard..."
streamlit run dashboard/streamlit_app.py --server.port 8501 --server.address 0.0.0.0