# 🛡️ Spear-Phishing & Social Engineering Profiler
### *AI-Assisted Human Attack Surface & Social Engineering Defense Auditor*

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](LICENSE)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.30%2B-FF4B4B.svg?style=for-the-badge&logo=Streamlit&logoColor=white)](https://streamlit.io/)
[![Framework](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK%20%2F%20NIST%20CSF-orange.svg?style=for-the-badge)](https://attack.mitre.org/)
[![Code Style: Black](https://img.shields.io/badge/code%20style-black-000000.svg?style=for-the-badge)](https://github.com/psf/black)

A comprehensive defensive OSINT reconnaissance, human risk profiling, and anti-spoofing platform. Computes an enterprise **Social Engineering Risk Index (SERI)**, models department pretexting susceptibility, and generates CISO-grade remediation playbooks.

---

## 📌 Overview

Traditional cybersecurity solutions guard endpoints and network perimeters, yet **over 80% of enterprise security breaches originate through human deception**—spear-phishing, Business Email Compromise (BEC), OAuth consent phishing, and MFA push fatigue.

The **Spear-Phishing & Social Engineering Profiler** bridges the gap between external OSINT signals and internal human risk. By non-intrusively gathering public DNS posture, evaluating email spoofability (SPF/DMARC), identifying exposed SaaS platforms, and mapping departmental privilege hierarchies, it quantifies an organization's susceptibility to social engineering before adversaries can exploit it.

---

## ⚡ Key Features

| Capability | Technical Scope & Defensive Impact |
| :--- | :--- |
| **🌐 Passive OSINT & Anti-Spoofing** | Evaluates **DMARC** (`p=none`, `quarantine`, `reject`) and **SPF** (`-all`, `~all`, `?all`) to detect whether attackers can forge official emails directly into victim inboxes. |
| **☁️ SaaS Footprint Detection** | Passively uncovers exposed cloud identities & tools (Microsoft 365, Google Workspace, Okta IdP, Jira, Slack, Salesforce, VPN portals). |
| **👥 Human Attack Surface Modeling** | Categorizes risk across departments (Execs, Finance, IT/DevOps, HR, Sales, Legal) based on access privileges and public OSINT visibility. |
| **🧠 Behavioral & Pretexting Engine** | Synthesizes department-tailored spear-phishing scenarios, identifying cognitive vulnerabilities (**Authority Bias, Urgency, Obligation**) and defensive detection indicators. |
| **🤖 Dual AI Engine** | Operates with a **built-in deterministic intelligence engine** (100% offline, zero-latency) with optional support for **Gemini 1.5 Flash** for generative reasoning. |
| **🛡️ CISO Remediation Playbooks** | Generates prioritized technical controls, governance policies (e.g. Out-of-Band wire verification), and a 30-60-90 day remediation roadmap. |
| **📄 Publication-Ready Reports** | Exports comprehensive audit briefs in **Markdown (`.md`)** and modern cyber-styled **HTML (`.html`)**. |

---
## 📁 Project Architecture

```
Spear-Phising & Social Engineering Profiler/
│
├── core/
│   ├── osint_collector.py       # Domain MX, SPF, DMARC lookups & SaaS footprinting
│   ├── org_mapper.py            # Department privilege & exposure surface modeling
│   ├── risk_scorer.py           # Social Engineering Risk Index (SERI) calculation
│   ├── ai_profiler.py           # Behavioral triggers & pretexting scenario synthesis
│   └── defense_advisor.py       # Technical controls, governance, & training curriculum
│
├── data/
│   ├── sample_profiles.json     # Ready-to-audit enterprise profiles (FinTech, Healthcare, SaaS)
│   └── threat_catalog.json      # MITRE ATT&CK mapped social engineering TTPs
│
├── reports/
│   ├── report_generator.py      # Generates Markdown and standalone styled HTML reports
│   └── audit_*.html             # Saved audit reports
│
├── tests/
│   └── test_profiler.py         # Automated unit and integration test suite
│
├── app.py                       # Interactive Streamlit Web Operations Center
├── cli.py                       # Rich-formatted interactive command-line auditor
├── config.py                    # Risk weights, threat matrices, and configurations
├── requirements.txt             # Dependencies
└── README.md                    # System documentation
```

---

## 💻 Quickstart & Usage

### 1. Installation
Ensure Python 3.10+ is installed, then install requirements:
```bash
pip install -r requirements.txt
```

### 2. Run the Streamlit SOC Web Dashboard
Launch the interactive web user interface:
```bash
streamlit run app.py
```
Open your browser at `http://localhost:8501` to:
- Select from bundled benchmark enterprises (Apex FinTech, CloudScale AI, BioCare Health) or input custom domains.
- Explore interactive department heatmaps, SERI gauge meters, and pretexting scenarios.
- Download CISO-ready Markdown and HTML audit reports with one click.

### 3. Run the CLI Scanner
Audit any domain directly from your terminal with rich color formatting:

Audit using a benchmark profile:
```bash
python cli.py --profile ApexFintech
```

Audit an arbitrary domain:
```bash
python cli.py --domain target-company.com
```

### 4. Run Automated Unit Tests
```bash
python -m unittest tests/test_profiler.py
```

---

## ⚖️ Ethics & Defensive Security Statement
This tool is developed strictly for **defensive security auditing, organizational risk assessment, and employee security awareness training**. It does not deliver live emails, exploit vulnerabilities, or harvest credentials.
