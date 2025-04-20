import streamlit as st
import pandas as pd
import json
import plotly.express as px
import ollama
from ollama import Client

# Helper to query LLaMA 3 via Ollama
def get_fix_from_llm(prompt):
    try:
        client = Client(host="http://host.docker.internal:11434")
        response = client.chat(
            model="llama3",
            messages=[{"role": "user", "content": prompt}]
        )
        return response["message"]["content"]
    except Exception as e:
        return f"⚠️ Failed to get suggestion: {str(e)}"

def format_suggestion(suggestion):
    lines = suggestion.replace("•", "\n-").split("\n")
    return "\n".join(line.strip() for line in lines if line.strip())

# Load prioritized CVEs
with open("/scanner_output/target/", "r") as f:
    cves = json.load(f)

df = pd.DataFrame(cves)

# UI Setup
st.set_page_config(page_title="RBVM Dashboard", layout="wide")
st.title("🛡️ Risk-Based Vulnerability Management Dashboard")

# Summary Metrics
col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("Total CVEs", len(df))
col2.metric("Act ASAP", len(df[df["decision"] == "Act ASAP"]))
col3.metric("Act", len(df[df["decision"] == "Act"]))
col4.metric("Track", len(df[df["decision"].isin(["Track", "Track Closely (No Fix)"])]))
col5.metric("Defer", len(df[df["decision"] == "Defer"]))

# Sidebar Filters
st.sidebar.header("🔍 Filters")
decision_filter = st.sidebar.selectbox("Filter by Decision", options=["All", "Act ASAP", "Act", "Track", "Defer"])
only_actionable = st.sidebar.checkbox("Only actionable (fix available)", value=True)
search_term = st.sidebar.text_input("🔎 Search CVE ID or Package")

# Apply filters
filtered_df = df.copy()
if decision_filter != "All":
    filtered_df = filtered_df[filtered_df["decision"] == decision_filter]
if only_actionable:
    filtered_df = filtered_df[filtered_df["actionable"] == True]
if search_term:
    filtered_df = filtered_df[
        filtered_df["cve_id"].str.contains(search_term, case=False) |
        filtered_df["package"].str.contains(search_term, case=False)
    ]

filtered_df = filtered_df.sort_values(by="risk_score", ascending=False)

# Tabs
tab1, tab2, tab3 = st.tabs(["📋 Prioritized CVE Table", "🛠️ Fix Recommendations", "📈 Visual Risk Summary"])

with tab1:
    st.subheader("📊 CVE Details")
    st.dataframe(filtered_df[[
        "cve_id", "package", "cvss", "epss_score",
        "risk_score", "risk_band", "decision", "fixed_version", "justification"
    ]])

with tab2:
    st.subheader("🛠️ Fix Recommendations")
    act_df = filtered_df[filtered_df["decision"].isin(["Act", "Act ASAP"])]
    for index, row in act_df.iterrows():
        with st.expander(f"🧨 {row['cve_id']} in `{row['package']}`"):
            col1, col2 = st.columns([2, 1])
            with col1:
                st.markdown(f"""
                - **CVSS**: `{row['cvss']}`
                - **EPSS Score**: `{row['epss_score']}`
                - **Risk Score**: `{row['risk_score']}` ({row['risk_band']})
                - **Decision**: `{row['decision']}`
                - **Justification**: {row['justification']}
                """)

            # AI Fix Suggestion Button
            if st.button(f"💡 Suggest Fix with AI for {row['cve_id']}", key=f"{row['cve_id']}_{index}_ai"):
                with st.spinner("Asking LLaMA 3 for guidance..."):
                    prompt = f"""
You are a DevSecOps AI assistant. Suggest how to remediate or fix the following vulnerability:

- CVE ID: {row['cve_id']}
- Package: {row['package']}
- CVSS: {row['cvss']}
- EPSS Score: {row['epss_score']}
- Fix Available: {row['fix_available']}
- Fix Version: {row['fixed_version']}
- Risk Band: {row['risk_band']}
- Justification: {row['justification']}

Instructions:
1. If a fixed version is known, return it clearly in the format: "Fixed version: x.y.z"
2. If no fixed version is available, suggest a mitigation.
3. Return the recommended command (e.g., apt upgrade, pip install, etc.) if appropriate.
4. Respond in a bullet-point format.
"""
                    suggestion = get_fix_from_llm(prompt)
                    formatted = format_suggestion(suggestion)
                    st.markdown("**💡 AI Fix Suggestion:**")
                    st.markdown(formatted)

with tab3:
    st.subheader("📈 Risk Distribution")

    decision_colors = {
        "Act ASAP": "#e74c3c",
        "Act": "#f39c12",
        "Track": "#3498db",
        "Defer": "#95a5a6"
    }

    risk_band_colors = {
        "Critical": "#c0392b",
        "High": "#d35400",
        "Medium": "#2980b9",
        "Low": "#7f8c8d"
    }

    col1, col2 = st.columns(2)

    with col1:
        decision_count = df["decision"].value_counts().reset_index()
        decision_count.columns = ["Decision", "Count"]
        fig = px.pie(
            decision_count,
            values="Count",
            names="Decision",
            title="Decision Breakdown",
            color="Decision",
            color_discrete_map=decision_colors
        )
        fig.update_traces(textinfo="label+percent", pull=[0.05]*len(decision_count))
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        risk_band_count = df["risk_band"].value_counts().reset_index()
        risk_band_count.columns = ["Risk Band", "Count"]
        fig2 = px.pie(
            risk_band_count,
            values="Count",
            names="Risk Band",
            title="Risk Band Distribution",
            color="Risk Band",
            color_discrete_map=risk_band_colors
        )
        fig2.update_traces(textinfo="label+percent", pull=[0.05]*len(risk_band_count))
        st.plotly_chart(fig2, use_container_width=True)

    st.markdown("### 📊 Risk Score Distribution")
    fig3 = px.histogram(df, x="risk_score", nbins=20, title="Risk Score Histogram", color="decision",
                        color_discrete_map=decision_colors)
    st.plotly_chart(fig3, use_container_width=True)
