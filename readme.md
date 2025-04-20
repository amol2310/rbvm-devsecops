# 🛡️ RBVM DevSecOps Pipeline – Vulnerability Prioritization with AI Fix Guidance

This repository implements a complete Risk-Based Vulnerability Management (RBVM) scanner integrated into a DevSecOps pipeline. It uses image scanning, risk enrichment, AI-driven remediation suggestions, and a user-friendly dashboard for actionable vulnerability triage.

---

## 🚀 Features

- 🔍 Trivy-based Docker image vulnerability scanning
- 🧠 Risk-based prioritization using CVSS, EPSS, CISA KEV, and fix availability
- 💡 AI-generated remediation advice using [Ollama](https://ollama.com) and LLaMA 3
- 📊 Interactive Streamlit dashboard for security decision-makers
- ✅ Output includes JSON with actionable decisions (`Act ASAP`, `Act`, `Track`, `Defer`)

---

## 📁 Project Structure

```
rbvm-devsecops/
├── scanners/              # Contains Trivy wrapper script
├── ingestion/             # Normalizes scanner output
├── enrichment/            # Adds CVSS, EPSS, KEV metadata
├── decision_engine/       # Prioritization engine using decision trees
├── dashboard/             # Streamlit UI to view actionable CVEs
├── reports/               # Optional CSV/HTML reporting scripts
├── entrypoint.sh          # Orchestrates the pipeline
├── run.sh                 # Simple local runner script
├── Dockerfile             # Containerized scanner and dashboard
└── requirements.txt       # Python dependencies
```

---

## ⚙️ How to Use

Please check out the demo project here
https://github.com/amol2310/rbvm-demo/tree/main
Docker image: 
```docker pull maratheamol2310/rbvm:1.0.2```

## 👨‍💻 Author

Developed by [Amol Marathe](https://github.com/amolmarathe)  
As part of DevSecOps MTech Dissertation Project


