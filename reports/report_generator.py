"""
Report Generator module: compiles executive CISO briefs, full risk breakdowns,
and defensive playbooks into publication-ready Markdown and standalone styled HTML reports.
"""

import datetime
from pathlib import Path
from typing import Dict, Any
from config import REPORTS_DIR

class ReportGenerator:
    """Generates Markdown and HTML audit reports."""

    def __init__(self):
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    def generate_markdown_report(
        self,
        domain_recon: Dict[str, Any],
        org_model: Dict[str, Any],
        seri_results: Dict[str, Any],
        ai_profile: Dict[str, Any],
        defense_plan: Dict[str, Any]
    ) -> str:
        """Assembles a comprehensive Markdown audit brief."""
        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        org_name = org_model.get("name", "Target Organization")
        domain = domain_recon.get("domain", "target-domain.com")
        score = seri_results.get("seri_score", 0.0)
        tier = seri_results.get("risk_tier", "UNKNOWN")
        badge = seri_results.get("badge", "")

        md = f"""# 🛡️ Executive Security Audit Brief: Social Engineering & Spear-Phishing Exposure
**Target Organization**: {org_name}  
**Primary Domain**: `{domain}`  
**Scan Timestamp**: {now_str}  
**Assessment Standard**: MITRE ATT&CK for Enterprise & NIST CSF  

---

## 📊 1. Executive Summary & SERI Scorecard

| Metric | Score / Status | Assessment |
| :--- | :--- | :--- |
| **Social Engineering Risk Index (SERI)** | **`{score} / 100`** | **{badge}** |
| **Domain Spoofability** | `{seri_results['component_scores']['domain_spoof_risk']['score']} / 100` | DMARC: `{domain_recon.get('dmarc', {}).get('policy', 'none')}` | SPF: `{domain_recon.get('spf', {}).get('qualifier', 'unknown')}` |
| **Human Attack Surface Risk** | `{seri_results['component_scores']['human_attack_surface_risk']['score']} / 100` | Headcount: `{org_model.get('employee_count', 0)}` across `{len(org_model.get('departments', []))}` departments |
| **SaaS & Tech Stack Risk** | `{seri_results['component_scores']['tech_stack_exposure_risk']['score']} / 100` | `{len(domain_recon.get('tech_stack', []))}` public SaaS attack vectors detected |

### 💡 Executive Takeaway
> {ai_profile.get('executive_takeaway', 'Organization requires enhanced human defense posture.')}

### 🚨 Primary Risk Drivers
"""
        for driver in seri_results.get("top_drivers", []):
            md += f"- ⚠️ **{driver}**\n"

        md += f"""
---

## 🌐 2. Technical Domain & OSINT Footprint Analysis

- **DMARC Record**: `{domain_recon.get('dmarc', {}).get('raw') or 'NOT DETECTED'}`
  - **Policy**: `{domain_recon.get('dmarc', {}).get('policy')}`
  - **Evaluation**: {domain_recon.get('dmarc', {}).get('description')}
- **SPF Record**: `{domain_recon.get('spf', {}).get('raw') or 'NOT DETECTED'}`
  - **Qualifier**: `{domain_recon.get('spf', {}).get('qualifier')}`
  - **Evaluation**: {domain_recon.get('spf', {}).get('description')}
- **Spoofability Summary**: {domain_recon.get('spoof_assessment', {}).get('summary')}

### Detected SaaS & Collaboration Footprint
"""
        if domain_recon.get("tech_stack"):
            md += "| Platform | Indicator Found | Potential Threat Vector |\n| :--- | :--- | :--- |\n"
            for t in domain_recon["tech_stack"]:
                md += f"| **{t['name']}** | `{t['indicator_found']}` | {t['threat_vector']} |\n"
        else:
            md += "_No high-profile SaaS indicators uncovered in passive DNS telemetry._\n"

        md += f"""
### Inferred Corporate Email Conventions
"""
        for p in domain_recon.get("inferred_email_patterns", []):
            md += f"- `{p['format']}` (Example: `{p['example']}`) — *{p['popularity']}*\n"

        md += f"""
---

## 👥 3. Department Vulnerability & Susceptibility Matrix

| Department | Headcount | Privilege Tier | Exposure | Dept Risk | Firewall Readiness |
| :--- | :--- | :--- | :--- | :--- | :--- |
"""
        for dept in ai_profile.get("department_profiles", []):
            readiness = dept.get("human_firewall_readiness", {})
            md += f"| **{dept['department']}** | {dept['headcount']} | {dept['criticality']} | High | `{dept['risk_score']}/100` | **{readiness.get('rating', 'UNKNOWN')}** |\n"

        md += f"""
---

## 🎯 4. Pretexting Scenarios & Cognitive Triggers (By Department)
"""
        for dept in ai_profile.get("department_profiles", []):
            md += f"\n### 🏢 {dept['department']}\n"
            md += "**Cognitive Vulnerabilities:**\n"
            for cog in dept.get("cognitive_vulnerabilities", []):
                md += f"- **{cog['trigger']}**: {cog['vulnerability']}\n"
            
            md += "\n**Plausible Pretexting Scenarios:**\n"
            for sc in dept.get("plausible_scenarios", []):
                md += f"""
> #### 📌 {sc['scenario_title']}
> - **Threat Vector / MITRE**: {sc['threat_vector']} (`{sc.get('mitre_technique', 'T1566')}`)
> - **Attacker Pretext**: {sc['attacker_pretext']}
> - **Psychological Hook**: `{sc['psychological_hook']}`
> - **Employee Blindspot**: {sc['employee_cognitive_blindspot']}
> - **Defensive Indicator**: `{sc['defensive_indicator']}`
"""

        md += f"""
---

## 🛡️ 5. CISO Remediation Playbook & Training Curriculum

### Top Urgent Priorities
"""
        for p in defense_plan.get("executive_priorities", []):
            md += f"1. 🎯 **{p}**\n"

        md += f"""
### Mandatory Technical Controls
"""
        for c in defense_plan.get("technical_controls", []):
            md += f"""
#### 🔧 {c['control']} [{c['urgency']}]
- **Category**: {c['category']}
- **Rationale**: {c['rationale']}
- **Action Steps**:
"""
            for step in c.get("implementation_steps", []):
                md += f"  - {step}\n"

        md += f"""
### Governance Policies & Protocols
"""
        for pol in defense_plan.get("procedural_policies", []):
            md += f"- **{pol['policy_name']}**: {pol['rule']} *(Benefit: {pol['benefit']})*\n"

        md += f"""
### Implementation Timeline (30-60-90 Days)
"""
        for phase, items in defense_plan.get("implementation_timeline", {}).items():
            md += f"\n**{phase}**:\n"
            for item in items:
                md += f"- [ ] {item}\n"

        md += "\n---\n*Report generated autonomously by Spear-Phishing & Social Engineering Profiler (Defensive Security Standard).*\n"
        return md

    def generate_html_report(
        self,
        domain_recon: Dict[str, Any],
        org_model: Dict[str, Any],
        seri_results: Dict[str, Any],
        ai_profile: Dict[str, Any],
        defense_plan: Dict[str, Any]
    ) -> str:
        """Generates a standalone, polished HTML audit brief with modern cyber dark-mode styling."""
        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        org_name = org_model.get("name", "Target Organization")
        domain = domain_recon.get("domain", "target-domain.com")
        score = seri_results.get("seri_score", 0.0)
        tier = seri_results.get("risk_tier", "UNKNOWN")
        badge = seri_results.get("badge", "")
        color = seri_results.get("color", "#ffc107")

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Audit Brief - {org_name}</title>
<style>
  :root {{
    --bg-main: #0d1117;
    --bg-card: #161b22;
    --border: #30363d;
    --text-primary: #c9d1d9;
    --text-heading: #f0f6fc;
    --accent: #58a6ff;
    --accent-red: #f85149;
    --accent-green: #3fb950;
    --accent-yellow: #d29922;
  }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background-color: var(--bg-main);
    color: var(--text-primary);
    line-height: 1.6;
    margin: 0;
    padding: 30px 20px;
  }}
  .container {{
    max-width: 1000px;
    margin: 0 auto;
  }}
  .header-card {{
    background: linear-gradient(135deg, #161b22 0%, #1f242c 100%);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 28px;
    margin-bottom: 25px;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }}
  .score-badge {{
    text-align: center;
    padding: 16px 24px;
    border-radius: 10px;
    background: rgba(0,0,0,0.4);
    border: 2px solid {color};
  }}
  .score-value {{
    font-size: 42px;
    font-weight: 800;
    color: {color};
    line-height: 1;
  }}
  .score-tier {{
    font-size: 13px;
    font-weight: 700;
    letter-spacing: 1px;
    text-transform: uppercase;
    color: {color};
    margin-top: 6px;
  }}
  h1, h2, h3, h4 {{
    color: var(--text-heading);
  }}
  .card {{
    background-color: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 22px;
    margin-bottom: 22px;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    margin: 15px 0;
  }}
  th, td {{
    padding: 12px 14px;
    text-align: left;
    border-bottom: 1px solid var(--border);
  }}
  th {{
    background-color: #21262d;
    color: var(--text-heading);
    font-size: 13px;
    text-transform: uppercase;
  }}
  .pill {{
    display: inline-block;
    padding: 3px 9px;
    border-radius: 12px;
    font-size: 12px;
    font-weight: 600;
  }}
  .pill-red {{ background: rgba(248, 81, 73, 0.2); color: #f85149; border: 1px solid #f85149; }}
  .pill-yellow {{ background: rgba(210, 153, 34, 0.2); color: #d29922; border: 1px solid #d29922; }}
  .pill-green {{ background: rgba(63, 185, 80, 0.2); color: #3fb950; border: 1px solid #3fb950; }}
  .scenario-box {{
    background: #0d1117;
    border-left: 4px solid var(--accent);
    padding: 16px;
    border-radius: 0 8px 8px 0;
    margin-bottom: 15px;
  }}
  code {{
    background: #21262d;
    padding: 2px 6px;
    border-radius: 4px;
    font-family: Consolas, Monaco, monospace;
    font-size: 13px;
    color: var(--accent);
  }}
</style>
</head>
<body>
<div class="container">
  <div class="header-card">
    <div>
      <h1 style="margin:0 0 8px 0;">🛡️ Spear-Phishing & Social Engineering Audit</h1>
      <p style="margin:0; color:#8b949e;">Organization: <strong style="color:#f0f6fc;">{org_name}</strong> | Domain: <code>{domain}</code></p>
      <p style="margin:4px 0 0 0; font-size:12px; color:#8b949e;">Generated: {now_str} | Standard: MITRE ATT&CK Enterprise</p>
    </div>
    <div class="score-badge">
      <div class="score-value">{score}</div>
      <div class="score-tier">{tier} RISK</div>
    </div>
  </div>

  <div class="card">
    <h2>📊 Executive Assessment & SERI Index Breakdown</h2>
    <p>{ai_profile.get('executive_takeaway', '')}</p>
    <table>
      <thead>
        <tr><th>Security Dimension</th><th>Risk Score</th><th>Weight</th><th>Weighted Impact</th></tr>
      </thead>
      <tbody>
        <tr>
          <td><strong>Domain Email Spoofability (DMARC / SPF)</strong></td>
          <td><span class="pill {'pill-red' if seri_results['component_scores']['domain_spoof_risk']['score'] > 60 else 'pill-green'}">{seri_results['component_scores']['domain_spoof_risk']['score']} / 100</span></td>
          <td>35%</td>
          <td>{seri_results['component_scores']['domain_spoof_risk']['weighted_contribution']} pts</td>
        </tr>
        <tr>
          <td><strong>Human Attack Surface (Departments & Exposure)</strong></td>
          <td><span class="pill {'pill-red' if seri_results['component_scores']['human_attack_surface_risk']['score'] > 60 else 'pill-yellow'}">{seri_results['component_scores']['human_attack_surface_risk']['score']} / 100</span></td>
          <td>40%</td>
          <td>{seri_results['component_scores']['human_attack_surface_risk']['weighted_contribution']} pts</td>
        </tr>
        <tr>
          <td><strong>Tech Stack & SaaS Infiltration Surface</strong></td>
          <td><span class="pill {'pill-yellow' if seri_results['component_scores']['tech_stack_exposure_risk']['score'] > 60 else 'pill-green'}">{seri_results['component_scores']['tech_stack_exposure_risk']['score']} / 100</span></td>
          <td>25%</td>
          <td>{seri_results['component_scores']['tech_stack_exposure_risk']['weighted_contribution']} pts</td>
        </tr>
      </tbody>
    </table>
  </div>

  <div class="card">
    <h2>🏢 Departmental Susceptibility Analysis</h2>
    <table>
      <thead>
        <tr><th>Department</th><th>Headcount</th><th>Privilege</th><th>Vulnerability</th><th>Human Firewall Readiness</th></tr>
      </thead>
      <tbody>
"""
        for dept in ai_profile.get("department_profiles", []):
            readiness = dept.get("human_firewall_readiness", {})
            r_class = "pill-red" if readiness.get("rating") == "VULNERABLE" else "pill-yellow" if "MODERATE" in readiness.get("rating", "") else "pill-green"
            html += f"""        <tr>
          <td><strong>{dept['department']}</strong></td>
          <td>{dept['headcount']}</td>
          <td><code>{dept['criticality']}</code></td>
          <td><strong>{dept['risk_score']} / 100</strong></td>
          <td><span class="pill {r_class}">{readiness.get('rating', 'UNKNOWN')}</span></td>
        </tr>
"""

        html += f"""      </tbody>
    </table>
  </div>

  <div class="card">
    <h2>🎯 Target Pretexting Scenarios</h2>
"""
        for dept in ai_profile.get("department_profiles", []):
            html += f"<h3 style='margin-top:20px; color:#58a6ff;'>🏢 {dept['department']}</h3>"
            for sc in dept.get("plausible_scenarios", []):
                html += f"""    <div class="scenario-box">
      <h4 style="margin:0 0 6px 0; color:#f0f6fc;">📌 {sc['scenario_title']} <span class="pill pill-yellow">{sc.get('mitre_technique', 'T1566')}</span></h4>
      <p style="margin:4px 0;"><strong>Attacker Pretext:</strong> {sc['attacker_pretext']}</p>
      <p style="margin:4px 0; color:#8b949e;"><strong>Psychological Hook:</strong> {sc['psychological_hook']}</p>
      <p style="margin:4px 0; color:#e3b341;"><strong>Cognitive Blindspot:</strong> {sc['employee_cognitive_blindspot']}</p>
      <p style="margin:4px 0; color:#3fb950;"><strong>Defensive Indicator:</strong> <code>{sc['defensive_indicator']}</code></p>
    </div>
"""

        html += f"""  </div>

  <div class="card">
    <h2>🛡️ Mandatory Defensive Countermeasures</h2>
"""
        for c in defense_plan.get("technical_controls", []):
            p_class = "pill-red" if "IMMEDIATE" in c.get("urgency", "") else "pill-yellow"
            html += f"""    <div style="margin-bottom:18px; padding-bottom:14px; border-bottom:1px solid #30363d;">
      <h4 style="margin:0 0 6px 0;">🔧 {c['control']} <span class="pill {p_class}">{c['urgency']}</span></h4>
      <p style="margin:4px 0; color:#8b949e;">{c['rationale']}</p>
      <ul>
"""
            for step in c.get("implementation_steps", []):
                html += f"        <li>{step}</li>"
            html += """      </ul>
    </div>
"""

        html += """  </div>
</div>
</body>
</html>
"""
        return html

    def save_reports(
        self,
        domain: str,
        md_content: str,
        html_content: str
    ) -> Dict[str, Path]:
        """Saves reports to disk in reports/ directory."""
        clean_domain = domain.replace(".", "_").replace("/", "")
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        md_file = REPORTS_DIR / f"audit_{clean_domain}_{timestamp}.md"
        html_file = REPORTS_DIR / f"audit_{clean_domain}_{timestamp}.html"
        
        with open(md_file, "w", encoding="utf-8") as f:
            f.write(md_content)
            
        with open(html_file, "w", encoding="utf-8") as f:
            f.write(html_content)
            
        return {"md": md_file, "html": html_file}
