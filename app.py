"""
app.py — ThreatCheck AI Streamlit dashboard.

Handles all UI: page layout, sidebar settings, indicator input, analysis
workflow, results display, scan history, and JSON export. All business
logic lives in source.py.
"""

import json
import os
from datetime import datetime, timezone

import streamlit as st

import source

# --------------------------------------------------------------------------- #
# Page configuration
# --------------------------------------------------------------------------- #

st.set_page_config(
    page_title="ThreatCheck AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

DARK_CSS = """
<style>
.stApp { background-color: #0b0f14; }
.tc-card {
    background-color: #131a22;
    border: 1px solid #22303c;
    border-radius: 10px;
    padding: 1.1rem 1.3rem;
    margin-bottom: 1rem;
}
.tc-badge {
    display: inline-block;
    font-size: 1.05rem;
    font-weight: 700;
    padding: 0.35rem 0.9rem;
    border-radius: 999px;
    background-color: #1b2530;
    border: 1px solid #2c3b48;
}
.tc-score {
    font-size: 2.6rem;
    font-weight: 800;
    line-height: 1;
}
.tc-muted { color: #8a9aa8; font-size: 0.88rem; }
.tc-finding { padding: 0.15rem 0; }
.tc-section-title {
    font-size: 1.05rem;
    font-weight: 700;
    margin-bottom: 0.4rem;
    color: #e7edf3;
}
</style>
"""
st.markdown(DARK_CSS, unsafe_allow_html=True)


# --------------------------------------------------------------------------- #
# Session state initialization
# --------------------------------------------------------------------------- #

def init_session_state() -> None:
    defaults = {
        "vt_api_key": os.environ.get("VT_API_KEY", ""),
        "gemini_api_key": os.environ.get("GEMINI_API_KEY", ""),
        "scan_history": [],
        "last_result": None,
        "keys_saved_flag": False,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

    # Fall back to Streamlit secrets if present and env vars were empty.
    if not st.session_state["vt_api_key"]:
        try:
            st.session_state["vt_api_key"] = st.secrets.get("VT_API_KEY", "")
        except Exception:
            pass
    if not st.session_state["gemini_api_key"]:
        try:
            st.session_state["gemini_api_key"] = st.secrets.get("GEMINI_API_KEY", "")
        except Exception:
            pass


init_session_state()


# --------------------------------------------------------------------------- #
# Sidebar — settings
# --------------------------------------------------------------------------- #

def render_sidebar() -> None:
    with st.sidebar:
        st.markdown("## ⚙️ Settings")
        st.markdown("#### API Keys")
        st.caption(
            "Keys are kept only in this browser session. They are never logged, "
            "displayed after entry, or sent to Gemini."
        )

        with st.form("api_key_form", clear_on_submit=False):
            vt_input = st.text_input(
                "VirusTotal API Key",
                type="password",
                placeholder="Enter VirusTotal API key",
            )
            gemini_input = st.text_input(
                "Gemini API Key",
                type="password",
                placeholder="Enter Google Gemini API key",
            )
            saved = st.form_submit_button("💾 Save API Keys")

        if saved:
            if vt_input:
                st.session_state["vt_api_key"] = vt_input.strip()
            if gemini_input:
                st.session_state["gemini_api_key"] = gemini_input.strip()
            st.session_state["keys_saved_flag"] = True

        if st.session_state["keys_saved_flag"]:
            st.success("API keys saved for this session.")

        vt_status = "✅ Configured" if st.session_state["vt_api_key"] else "❌ Not set"
        gemini_status = "✅ Configured" if st.session_state["gemini_api_key"] else "❌ Not set"
        st.markdown(f"**VirusTotal:** {vt_status}")
        st.markdown(f"**Gemini:** {gemini_status}")

        st.divider()
        st.markdown("#### Recent Scans")
        render_scan_history_sidebar()

        st.divider()
        st.caption(
            "ThreatCheck AI combines VirusTotal threat intelligence with "
            "Google Gemini AI-assisted analysis. Deterministic scoring from "
            "VirusTotal evidence is always authoritative."
        )


def render_scan_history_sidebar() -> None:
    history = st.session_state["scan_history"]
    if not history:
        st.caption("No scans yet this session.")
        return

    for entry in reversed(history[-10:]):
        badge = source.RISK_BADGE.get(entry["risk_level"], "⚪ UNKNOWN")
        st.markdown(
            f"**{entry['indicator']}**  \n"
            f"<span class='tc-muted'>{entry['indicator_type'].upper()} · {entry['timestamp']}</span>  \n"
            f"{badge} · {entry['risk_score']}/100",
            unsafe_allow_html=True,
        )
        st.markdown("---")

    if st.button("🗑️ Clear History"):
        st.session_state["scan_history"] = []
        st.rerun()


# --------------------------------------------------------------------------- #
# Main header
# --------------------------------------------------------------------------- #

def render_header() -> None:
    st.title("🛡️ ThreatCheck AI")
    st.markdown("##### AI-powered URL, Domain & IP Reputation Analyzer")
    st.markdown(
        "Analyze URLs, domains, and IP addresses using VirusTotal threat "
        "intelligence and Google Gemini AI-assisted analysis."
    )
    st.info(
        "🔒 **Privacy Notice:** Indicators submitted to this application may be sent to "
        "VirusTotal, and relevant security information may be processed by Google Gemini. "
        "Do not submit confidential indicators unless you are authorized to do so.",
        icon="🔒",
    )


# --------------------------------------------------------------------------- #
# Input section
# --------------------------------------------------------------------------- #

def render_input_section() -> tuple[str, str, bool]:
    st.markdown("### 🔎 Indicator Input")

    indicator_type_label = st.radio(
        "Indicator Type",
        options=["Auto Detect", "URL", "Domain", "IPv4", "IPv6"],
        horizontal=True,
    )
    type_map = {
        "Auto Detect": "auto",
        "URL": "url",
        "Domain": "domain",
        "IPv4": "ipv4",
        "IPv6": "ipv6",
    }
    declared_type = type_map[indicator_type_label]

    raw_value = st.text_input(
        "Enter URL, Domain, or IP Address",
        placeholder="https://example.com   |   example.com   |   8.8.8.8   |   2001:4860:4860::8888",
    )

    analyze_clicked = st.button("🔍 Analyze Indicator", type="primary", use_container_width=False)

    return raw_value, declared_type, analyze_clicked


# --------------------------------------------------------------------------- #
# Analysis execution with progress display
# --------------------------------------------------------------------------- #

def run_analysis(raw_value: str, declared_type: str):
    progress_box = st.empty()

    def show_progress(lines: list[str]) -> None:
        progress_box.markdown("\n".join(lines))

    steps = [
        "⏳ Validating indicator",
        "⏳ Detecting indicator type",
        "⏳ Querying VirusTotal",
        "⏳ Calculating risk",
        "⏳ Asking Gemini for analysis",
        "⏳ Preparing final report",
    ]
    show_progress(steps)

    try:
        clean_value, resolved_type = source.validate_indicator(raw_value, declared_type)
    except source.ValidationError as e:
        progress_box.empty()
        st.error(f"❌ {e}")
        return None

    steps[0] = "✅ Validating indicator"
    steps[1] = "✅ Detecting indicator type"
    show_progress(steps)

    result = source.build_final_result(
        indicator=clean_value,
        indicator_type=resolved_type,
        vt_api_key=st.session_state["vt_api_key"],
        gemini_api_key=st.session_state["gemini_api_key"],
    )

    steps[2] = "✅ Querying VirusTotal" if result.vt_available or result.vt_error is None else "⚠️ VirusTotal unavailable"
    steps[3] = "✅ Calculating risk"
    steps[4] = "✅ Asking Gemini for analysis" if result.gemini_available else "⚠️ Gemini unavailable"
    steps[5] = "✅ Preparing final report"
    show_progress(steps)

    progress_box.empty()
    return result


# --------------------------------------------------------------------------- #
# Results display
# --------------------------------------------------------------------------- #

def render_risk_panel(result) -> None:
    badge = source.RISK_BADGE.get(result.risk_level, "⚪ UNKNOWN")
    col1, col2, col3, col4 = st.columns([1.3, 1, 1, 1])

    with col1:
        st.markdown(
            f"<div class='tc-card'><div class='tc-muted'>Indicator</div>"
            f"<div style='font-size:1.2rem; font-weight:700; word-break:break-all;'>{result.indicator}</div>"
            f"<div class='tc-muted'>{result.indicator_type.upper()}</div></div>",
            unsafe_allow_html=True,
        )
    with col2:
        st.markdown(
            f"<div class='tc-card'><div class='tc-muted'>Security Risk</div>"
            f"<div class='tc-score'>{result.risk_score}/100</div>"
            f"<div class='tc-badge'>{badge}</div></div>",
            unsafe_allow_html=True,
        )
    with col3:
        st.markdown(
            f"<div class='tc-card'><div class='tc-muted'>Confidence</div>"
            f"<div style='font-size:1.4rem; font-weight:700;'>{result.confidence}</div></div>",
            unsafe_allow_html=True,
        )
    with col4:
        st.markdown(
            f"<div class='tc-card'><div class='tc-muted'>Scan Time</div>"
            f"<div style='font-size:1.0rem; font-weight:600;'>{result.timestamp}</div></div>",
            unsafe_allow_html=True,
        )


def render_executive_summary(result) -> None:
    st.markdown("<div class='tc-section-title'>📋 Executive Summary</div>", unsafe_allow_html=True)
    if not result.gemini_available and result.vt_error and not result.vt_available:
        st.error("Unable to complete the analysis because no threat intelligence sources are currently available.")
        return
    st.write(result.gemini_data.get("summary", "No summary available."))

    if not result.gemini_available:
        st.caption("AI summary unavailable. The assessment above is based on available threat intelligence.")


def render_key_findings(result) -> None:
    findings = result.gemini_data.get("key_findings") or []
    if not findings:
        return
    st.markdown("<div class='tc-section-title'>🔑 Key Findings</div>", unsafe_allow_html=True)
    for f in findings:
        st.markdown(f"<div class='tc-finding'>⚠️ {f}</div>", unsafe_allow_html=True)


def render_virustotal_section(result) -> None:
    st.markdown("<div class='tc-section-title'>🧪 VirusTotal Intelligence</div>", unsafe_allow_html=True)

    if result.vt_error and not result.vt_available:
        st.warning(f"VirusTotal analysis is currently unavailable. ({result.vt_error})")
        return

    vt = result.vt_data
    if not vt.get("available"):
        st.info("No VirusTotal data was found for this indicator yet.")
        return

    with st.expander("View VirusTotal details", expanded=True):
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Malicious", vt.get("malicious", 0))
        m2.metric("Suspicious", vt.get("suspicious", 0))
        m3.metric("Harmless", vt.get("harmless", 0))
        m4.metric("Undetected", vt.get("undetected", 0))

        st.markdown(f"**Reputation:** {vt.get('reputation', 'N/A')}")
        st.markdown(f"**Last analysis date:** {vt.get('last_analysis_date') or 'N/A'}")

        categories = vt.get("categories") or {}
        if categories:
            st.markdown("**Categories:** " + ", ".join(f"{k}: {v}" for k, v in categories.items()))

        tags = vt.get("tags") or []
        if tags:
            st.markdown("**Tags:** " + ", ".join(tags))

        if result.indicator_type in ("ipv4", "ipv6"):
            st.markdown(f"**ASN:** {vt.get('asn', 'N/A')}  |  **AS Owner:** {vt.get('as_owner', 'N/A')}")
            st.markdown(f"**Country:** {vt.get('country', 'N/A')}  |  **Network:** {vt.get('network', 'N/A')}")

        if result.indicator_type == "domain":
            st.markdown(f"**Registrar:** {vt.get('registrar', 'N/A')}")
            st.markdown(f"**WHOIS data available:** {'Yes' if vt.get('whois_available') else 'No'}")

        flagged = vt.get("flagged_vendors") or []
        if flagged:
            st.markdown("**Vendors flagging this indicator:**")
            for item in flagged:
                st.markdown(f"- `{item['vendor']}` → *{item['category']}* ({item.get('result') or 'n/a'})")


def render_gemini_section(result) -> None:
    st.markdown("<div class='tc-section-title'>🤖 Gemini Security Analysis</div>", unsafe_allow_html=True)

    if not result.gemini_available:
        st.warning("AI summary unavailable. The assessment shown is based on available threat intelligence.")

    data = result.gemini_data
    with st.expander("View AI analysis details", expanded=True):
        st.markdown(f"**Verdict:** {data.get('verdict', 'N/A')}")
        st.markdown(f"**Confidence:** {data.get('confidence', 'N/A')}")

        recs = data.get("recommendations") or []
        if recs:
            st.markdown("**Recommendations:**")
            for r in recs:
                st.markdown(f"- {r}")

        limitations = data.get("limitations")
        if limitations:
            st.markdown(f"**Limitations:** {limitations}")


def render_export_section(result) -> None:
    report = result.to_report_dict()
    report_json = json.dumps(report, indent=2, default=str)
    st.download_button(
        "⬇️ Download JSON Report",
        data=report_json,
        file_name=f"threatcheck_{result.indicator_type}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json",
        mime="application/json",
    )


def add_to_history(result) -> None:
    st.session_state["scan_history"].append(
        {
            "timestamp": result.timestamp,
            "indicator": result.indicator,
            "indicator_type": result.indicator_type,
            "risk_level": result.risk_level,
            "risk_score": result.risk_score,
        }
    )


# --------------------------------------------------------------------------- #
# Main app flow
# --------------------------------------------------------------------------- #

def main() -> None:
    render_sidebar()
    render_header()

    raw_value, declared_type, analyze_clicked = render_input_section()

    if analyze_clicked:
        if not st.session_state["vt_api_key"] and not st.session_state["gemini_api_key"]:
            st.error(
                "❌ No API keys configured. Add a VirusTotal and/or Gemini API key in the "
                "sidebar Settings before analyzing an indicator."
            )
        else:
            result = run_analysis(raw_value, declared_type)
            if result is not None:
                st.session_state["last_result"] = result
                add_to_history(result)

    result = st.session_state.get("last_result")
    if result is not None:
        st.divider()
        render_risk_panel(result)
        st.markdown("")
        render_executive_summary(result)
        render_key_findings(result)
        st.markdown("")
        col_left, col_right = st.columns(2)
        with col_left:
            render_virustotal_section(result)
        with col_right:
            render_gemini_section(result)
        st.markdown("")
        render_export_section(result)


if __name__ == "__main__":
    main()
