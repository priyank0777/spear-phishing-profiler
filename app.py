"""
Streamlit Web Dashboard for Spear-Phising & Social Engineering Profiler.
Provides a modern dark-mode cybersecurity operations center for auditing
domain spoofability, human attack surfaces, SERI scores, and training playbooks.
"""

import streamlit as st
import pandas as pd
from datetime import datetime

from core.osint_collector import OSINTCollector
from core.org_mapper import OrgMapper
from core.risk_scorer import RiskScorer
from core.ai_profiler import AIProfiler
from core.defense_advisor import DefenseAdvisor
from reports.report_generator import ReportGenerator
from config import TECH_STACK_SIGNATURES, RISK_TIERS

# Page Configuration
st.set_page_config(
    page_title="Spear-Phishing & Social Engineering Profiler",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Cyber Dark CSS
st.markdown("""
<style>
    .main {
        background-color: #0e1117;
    }
    .stMetric {
        background-color: #161b22;
        border: 1px solid #30363d;
        border-radius: 8px;
        padding: 12px 16px;
    }
    .metric-container {
        display: flex;
        gap: 15px;
        margin-bottom: 20px;
    }
    .cyber-card {
        background-color: #161b22;
        border: 1px solid #30363d;
        border-radius: 10px;
        padding: 20px;
        margin-bottom: 18px;
    }
    .scenario-card {
        background-color: #0d1117;
        border-left: 4px solid #58a6ff;
        border-radius: 0 8px 8px 0;
        padding: 16px;
        margin-bottom: 14px;
    }
    .tag-critical {
        background-color: rgba(248, 81, 73, 0.2);
        color: #f85149;
        border: 1px solid #f85149;
        padding: 2px 8px;
        border-radius: 12px;
        font-size: 11px;
        font-weight: 600;
    }
    .tag-warning {
        background-color: rgba(210, 153, 34, 0.2);
        color: #d29922;
        border: 1px solid #d29922;
        padding: 2px 8px;
        border-radius: 12px;
        font-size: 11px;
        font-weight: 600;
    }
    .tag-secure {
        background-color: rgba(63, 185, 80, 0.2);
        color: #3fb950;
        border: 1px solid #3fb950;
        padding: 2px 8px;
        border-radius: 12px;
        font-size: 11px;
        font-weight: 600;
    }
</style>
""", unsafe_allow_html=True)

@st.cache_resource
def get_services():
    return {
        "collector": OSINTCollector(),
        "mapper": OrgMapper(),
        "scorer": RiskScorer(),
        "profiler": AIProfiler(),
        "advisor": DefenseAdvisor(),
        "reporter": ReportGenerator()
    }

services = get_services()

# Sidebar Setup
with st.sidebar:
    st.image("https://img.icons8.com/color/96/shield.png", width=64)
    st.title("🛡️ Profiler Console")
    st.caption("AI-Powered Human Attack Surface & Defense Auditor")
    st.markdown("---")

    st.subheader("🎯 Target Profile Selection")
    sample_options = ["Custom Domain / Organization"] + [p["name"] for p in services["mapper"].list_sample_profiles()]
    selected_option = st.selectbox("Select Target Benchmark", sample_options)

    if selected_option != "Custom Domain / Organization":
        # Find key
        profile_key = None
        for p in services["mapper"].list_sample_profiles():
            if p["name"] == selected_option:
                profile_key = p["key"]
                break
        sample_data = services["mapper"].get_sample_profile(profile_key)
        target_name = st.text_input("Organization Name", sample_data["name"])
        target_domain = st.text_input("Primary Domain", sample_data["domain"])
        target_industry = st.text_input("Industry", sample_data.get("industry", "Enterprise"))
    else:
        sample_data = None
        target_name = st.text_input("Organization Name", "Acme Corporation")
        target_domain = st.text_input("Primary Domain", "acme-corp.com")
        target_industry = st.selectbox("Industry", [
            "Financial Services & FinTech",
            "Enterprise Software & SaaS",
            "Healthcare & Life Sciences",
            "E-Commerce & Retail",
            "Critical Infrastructure & Manufacturing",
            "Government & Defense"
        ])

    st.markdown("---")
    st.subheader("🤖 AI Engine Settings")
    ai_mode = st.radio("Intelligence Engine", ["Deterministic Expert AI (Offline)", "Gemini 1.5 Flash (Generative)"], index=0)
    api_key_input = ""
    if "Gemini" in ai_mode:
        api_key_input = st.text_input("Gemini API Key", type="password", help="Enter optional Google Gemini API key for real-time generative reasoning.")

    scan_btn = st.button("🚀 Run Vulnerability Profile", type="primary", use_container_width=True)

# Main Screen State Management
if "audit_completed" not in st.session_state:
    st.session_state.audit_completed = False

if scan_btn or not st.session_state.audit_completed:
    with st.spinner("Conducting OSINT footprinting & behavioral vulnerability assessment..."):
        # 1. OSINT Collection
        domain_recon = services["collector"].inspect_domain(target_domain)
        
        # Merge sample DNS posture if test domain is offline
        if sample_data and sample_data.get("dns_posture") and domain_recon["dmarc"]["status"] == "missing":
            mock_dns = sample_data["dns_posture"]
            if mock_dns.get("dmarc_policy"):
                domain_recon["dmarc"]["policy"] = mock_dns["dmarc_policy"]
                domain_recon["dmarc"]["status"] = "configured"
            if mock_dns.get("spf_qualifier"):
                domain_recon["spf"]["qualifier"] = mock_dns["spf_qualifier"]
                domain_recon["spf"]["status"] = "configured"
            domain_recon["spoof_assessment"] = services["collector"]._assess_spoofability(domain_recon["dmarc"], domain_recon["spf"])
            if sample_data.get("tech_stack"):
                for ts in sample_data["tech_stack"]:
                    if not any(d["name"] == ts for d in domain_recon["tech_stack"]):
                        domain_recon["tech_stack"].append({
                            "name": ts,
                            "indicator_found": "Profile Catalog Signature",
                            "threat_vector": TECH_STACK_SIGNATURES.get(ts, {}).get("threat_vector", "Credential Lures"),
                            "risk_multiplier": TECH_STACK_SIGNATURES.get(ts, {}).get("risk_multiplier", 1.2)
                        })

        # 2. Org Mapping
        depts_data = sample_data.get("departments", []) if sample_data else services["mapper"].generate_default_departments()
        org_model = services["mapper"].build_custom_organization(target_name, target_domain, target_industry, depts_data)

        # 3. Risk Scoring (SERI)
        seri_results = services["scorer"].calculate_seri(domain_recon, org_model)

        # 4. AI Profiling
        active_key = api_key_input if "Gemini" in ai_mode else None
        ai_profile = services["profiler"].profile_organization(domain_recon, org_model, seri_results, api_key=active_key)

        # 5. Defense Advisor
        defense_plan = services["advisor"].generate_remediation_roadmap(domain_recon, org_model, seri_results)

        # Cache in session state
        st.session_state.domain_recon = domain_recon
        st.session_state.org_model = org_model
        st.session_state.seri_results = seri_results
        st.session_state.ai_profile = ai_profile
        st.session_state.defense_plan = defense_plan
        st.session_state.audit_completed = True

# Load from session state
domain_recon = st.session_state.domain_recon
org_model = st.session_state.org_model
seri_results = st.session_state.seri_results
ai_profile = st.session_state.ai_profile
defense_plan = st.session_state.defense_plan

# Top Header Title
st.title(f"🛡️ Security Audit: {org_model.get('name')}")
st.caption(f"Domain: `{domain_recon.get('domain')}` | Industry: **{org_model.get('industry')}** | Assessed: {datetime.now().strftime('%b %d, %Y')}")

# KPI Metrics Ribbon
col1, col2, col3, col4 = st.columns(4)
seri_val = seri_results["seri_score"]
tier_name = seri_results["risk_tier"]
tier_color = seri_results["color"]

with col1:
    st.metric(
        label="Social Engineering Risk Index (SERI)",
        value=f"{seri_val} / 100",
        delta=f"{tier_name} RISK",
        delta_color="inverse"
    )

with col2:
    spoof_stat = domain_recon["spoof_assessment"]["threat_level"]
    st.metric(
        label="Domain Spoofability Rating",
        value=spoof_stat,
        delta=f"DMARC: {domain_recon['dmarc'].get('policy', 'missing').upper()}",
        delta_color="off" if spoof_stat == "LOW" else "inverse"
    )

with col3:
    st.metric(
        label="Audited Human Attack Surface",
        value=f"{org_model.get('employee_count', 0)} Staff",
        delta=f"{len(org_model.get('departments', []))} Departments",
        delta_color="off"
    )

with col4:
    top_dept = seri_results["department_rankings"][0]["name"] if seri_results["department_rankings"] else "N/A"
    top_dept_score = seri_results["department_rankings"][0]["risk_score"] if seri_results["department_rankings"] else 0
    st.metric(
        label="Highest Susceptibility Dept",
        value=top_dept.split("&")[0].strip(),
        delta=f"Risk: {top_dept_score}/100",
        delta_color="inverse"
    )

st.markdown("---")

# Navigation Tabs
tab_exec, tab_osint, tab_org, tab_pretext, tab_ciso, tab_report = st.tabs([
    "📊 Executive Scorecard",
    "🌐 Domain & OSINT Recon",
    "👥 Human Attack Surface",
    "🎯 Pretexting & Cognitive Triggers",
    "🛡️ Remediation Playbooks",
    "📄 Audit Reports & Export"
])

# ----------------- TAB 1: EXECUTIVE SCORECARD -----------------
with tab_exec:
    st.subheader("📊 Social Engineering Risk Index (SERI) Breakdown")
    
    col_left, col_right = st.columns([1.2, 1])
    
    with col_left:
        st.markdown(f"""
        <div class="cyber-card">
            <h3 style="margin-top:0;">Executive Assessment Summary</h3>
            <p style="font-size:15px; color:#c9d1d9;">{ai_profile.get('executive_takeaway')}</p>
        </div>
        """, unsafe_allow_html=True)

        st.subheader("🚨 Primary Risk Drivers")
        for driver in seri_results.get("top_drivers", []):
            st.warning(driver)

    with col_right:
        st.markdown("<div class='cyber-card'><h4 style='margin-top:0;'>Pillars of the SERI Index</h4>", unsafe_allow_html=True)
        
        c_scores = seri_results["component_scores"]
        
        # Domain Spoofability
        st.write(f"**1. Domain Spoofability (35% Weight)**: `{c_scores['domain_spoof_risk']['score']}/100`")
        st.progress(int(c_scores['domain_spoof_risk']['score']))
        
        # Human Surface
        st.write(f"**2. Human Attack Surface Exposure (40% Weight)**: `{c_scores['human_attack_surface_risk']['score']}/100`")
        st.progress(int(c_scores['human_attack_surface_risk']['score']))

        # Tech Stack
        st.write(f"**3. Exposed SaaS & IdP Infrastructure (25% Weight)**: `{c_scores['tech_stack_exposure_risk']['score']}/100`")
        st.progress(int(c_scores['tech_stack_exposure_risk']['score']))

        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("---")
    st.subheader("📈 Department Vulnerability Comparison")
    dept_df = pd.DataFrame([
        {
            "Department": d["name"],
            "Risk Score": d["risk_score"],
            "Criticality": d["criticality"],
            "Headcount": d["headcount"]
        }
        for d in seri_results["department_rankings"]
    ])
    st.bar_chart(dept_df.set_index("Department")["Risk Score"], color="#f85149")


# ----------------- TAB 2: DOMAIN & OSINT RECON -----------------
with tab_osint:
    st.subheader("🌐 Passive DNS & Email Defense Posture")
    
    col_d1, col_d2 = st.columns(2)
    
    with col_d1:
        dmarc = domain_recon.get("dmarc", {})
        d_pol = dmarc.get("policy", "missing").upper()
        d_tag_class = "tag-secure" if d_pol == "REJECT" else "tag-warning" if d_pol == "QUARANTINE" else "tag-critical"
        
        st.markdown(f"""
        <div class="cyber-card">
            <h4>DMARC Policy: <span class="{d_tag_class}">{d_pol}</span></h4>
            <p><strong>Raw Record:</strong> <code>{dmarc.get('raw') or 'NOT CONFIGURED'}</code></p>
            <p><strong>Evaluation:</strong> {dmarc.get('description')}</p>
            <p><strong>Aggregate Reports (rua):</strong> <code>{dmarc.get('rua') or 'None detected'}</code></p>
        </div>
        """, unsafe_allow_html=True)

    with col_d2:
        spf = domain_recon.get("spf", {})
        s_qual = spf.get("qualifier", "missing").upper()
        s_tag_class = "tag-secure" if s_qual == "HARDFAIL" else "tag-warning" if s_qual == "SOFTFAIL" else "tag-critical"
        
        st.markdown(f"""
        <div class="cyber-card">
            <h4>SPF Configuration: <span class="{s_tag_class}">{s_qual}</span></h4>
            <p><strong>Raw Record:</strong> <code>{spf.get('raw') or 'NOT CONFIGURED'}</code></p>
            <p><strong>Evaluation:</strong> {spf.get('description')}</p>
            <p><strong>Risk Score:</strong> <code>{spf.get('risk_score', 90)} / 100</code></p>
        </div>
        """, unsafe_allow_html=True)

    st.subheader("☁️ Exposed SaaS Footprint & Identity Gateways")
    if domain_recon.get("tech_stack"):
        tech_df = pd.DataFrame(domain_recon["tech_stack"])
        st.dataframe(tech_df[["name", "indicator_found", "threat_vector"]], use_container_width=True)
    else:
        st.info("No high-profile third-party identity indicators identified via public DNS.")

    st.subheader("✉️ Inferred Public Corporate Email Conventions")
    email_cols = st.columns(len(domain_recon.get("inferred_email_patterns", [])))
    for idx, p in enumerate(domain_recon.get("inferred_email_patterns", [])):
        with email_cols[idx]:
            st.markdown(f"""
            <div class="cyber-card" style="text-align:center;">
                <code>{p['format']}</code>
                <p style="margin:4px 0; font-size:12px; color:#8b949e;">{p['popularity']}</p>
                <small style="color:#58a6ff;">{p['example']}</small>
            </div>
            """, unsafe_allow_html=True)


# ----------------- TAB 3: HUMAN ATTACK SURFACE -----------------
with tab_org:
    st.subheader("👥 Department Privilege Tiers & Attack Surface")
    
    org_table = []
    for d in org_model.get("departments", []):
        roles_str = ", ".join(d.get("sample_roles", []))
        org_table.append({
            "Department": d["name"],
            "Headcount": d["headcount"],
            "Privilege Level": d["privilege_level"],
            "OSINT Visibility": d["public_exposure"],
            "Susceptibility Score": f"{d['risk_score']} / 100",
            "Key Roles": roles_str
        })
    st.dataframe(pd.DataFrame(org_table), use_container_width=True)

    st.markdown("---")
    st.subheader("🎯 Primary Threat Vectors by Department")
    for d in org_model.get("departments", []):
        with st.expander(f"🏢 {d['name']} (Risk: {d['risk_score']}/100 - {d['criticality']})"):
            c1, c2 = st.columns(2)
            with c1:
                st.write("**Targeted Threat Vectors:**")
                for th in d.get("baseline_threats", []):
                    st.markdown(f"- 🔴 {th}")
            with c2:
                st.write("**Key Roles at Risk:**")
                for r in d.get("sample_roles", []):
                    st.markdown(f"- 👤 {r}")


# ----------------- TAB 4: PRETEXTING & COGNITIVE TRIGGERS -----------------
with tab_pretext:
    st.subheader("🎯 Department Pretexting Profiles & Cognitive Vulnerabilities")
    st.caption(f"Analysis generated by: **{ai_profile.get('engine_used', 'Expert AI Engine')}**")

    dept_select = st.selectbox("Select Department to Audit", [d["department"] for d in ai_profile.get("department_profiles", [])])
    
    current_dept = None
    for d in ai_profile.get("department_profiles", []):
        if d["department"] == dept_select:
            current_dept = d
            break

    if current_dept:
        st.markdown(f"### 🏢 {current_dept['department']} Profiling")
        
        # Psychological Triggers
        st.subheader("🧠 Cognitive Manipulation Triggers")
        for trig in current_dept.get("cognitive_vulnerabilities", []):
            st.info(f"**{trig['trigger']}**: {trig['vulnerability']}")

        # Plausible Scenarios
        st.subheader("📌 Plausible Spear-Phishing & Pretexting Scenarios")
        for sc in current_dept.get("plausible_scenarios", []):
            st.markdown(f"""
            <div class="scenario-card">
                <h4 style="margin:0 0 8px 0; color:#f0f6fc;">
                    {sc['scenario_title']} 
                    <span class="tag-warning">{sc.get('mitre_technique', 'T1566')}</span>
                </h4>
                <p style="margin:4px 0;"><strong>Attacker Pretext:</strong> {sc['attacker_pretext']}</p>
                <p style="margin:4px 0; color:#8b949e;"><strong>Psychological Hook:</strong> {sc['psychological_hook']}</p>
                <p style="margin:4px 0; color:#d29922;"><strong>Cognitive Blindspot:</strong> {sc['employee_cognitive_blindspot']}</p>
                <p style="margin:4px 0; color:#3fb950;"><strong>Defensive Indicator to Spot:</strong> <code>{sc['defensive_indicator']}</code></p>
            </div>
            """, unsafe_allow_html=True)


# ----------------- TAB 5: REMEDIATION PLAYBOOKS -----------------
with tab_ciso:
    st.subheader("🛡️ CISO Technical Countermeasures & Policy Roadmap")

    st.markdown("### 🎯 Immediate Executive Action Items")
    for prio in defense_plan.get("executive_priorities", []):
        st.error(f"P1 Action: {prio}")

    st.markdown("---")
    st.subheader("🔧 Mandatory Technical Controls")
    for ctrl in defense_plan.get("technical_controls", []):
        with st.expander(f"{ctrl['control']} — [{ctrl['urgency']}]"):
            st.write(f"**Category**: {ctrl['category']}")
            st.write(f"**Rationale**: {ctrl['rationale']}")
            st.write("**Action Steps**:")
            for s in ctrl.get("implementation_steps", []):
                st.markdown(f"- [ ] {s}")

    st.markdown("---")
    st.subheader("📋 Governance & Procedural Policies")
    for pol in defense_plan.get("procedural_policies", []):
        st.markdown(f"""
        <div class="cyber-card">
            <h4>{pol['policy_name']}</h4>
            <p><strong>Rule:</strong> {pol['rule']}</p>
            <p style="color:#3fb950;"><strong>Defensive Benefit:</strong> {pol['benefit']}</p>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")
    st.subheader("🗓️ 30-60-90 Day Remediation Timeline")
    for phase, tasks in defense_plan.get("implementation_timeline", {}).items():
        st.write(f"**{phase}**:")
        for t in tasks:
            st.markdown(f"- {t}")


# ----------------- TAB 6: EXPORT & AUDIT REPORTS -----------------
with tab_report:
    st.subheader("📄 Export Executive Security Audit Brief")
    st.caption("Generate publication-grade Markdown and styled HTML reports for leadership review.")

    # Generate documents
    md_report = services["reporter"].generate_markdown_report(domain_recon, org_model, seri_results, ai_profile, defense_plan)
    html_report = services["reporter"].generate_html_report(domain_recon, org_model, seri_results, ai_profile, defense_plan)

    col_btn1, col_btn2 = st.columns(2)
    with col_btn1:
        st.download_button(
            label="📥 Download Markdown Report (.md)",
            data=md_report,
            file_name=f"Security_Audit_{target_domain.replace('.', '_')}.md",
            mime="text/markdown",
            use_container_width=True
        )

    with col_btn2:
        st.download_button(
            label="📥 Download Polished HTML Report (.html)",
            data=html_report,
            file_name=f"Security_Audit_{target_domain.replace('.', '_')}.html",
            mime="text/html",
            use_container_width=True
        )

    st.markdown("---")
    st.subheader("👁️ Report Preview")
    st.markdown(md_report)
