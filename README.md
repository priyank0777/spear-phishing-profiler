# 🛡️ Spear-Phishing & Social Engineering Profiler

An AI-assisted defensive cybersecurity reconnaissance and human attack surface auditing tool. This system evaluates an organization's public domain defenses (SPF, DMARC, MX), models department-level exposure, calculates a composite **Social Engineering Risk Index (SERI)**, and synthesizes behavioral pretexting vulnerabilities and CISO remediation playbooks.

Aligned with **MITRE ATT&CK for Enterprise** (T1566, T1598, T1078) and the **NIST Cybersecurity Framework (CSF)**.

---

## 🚀 Key Capabilities

1. **Passive OSINT & Anti-Spoofing Audit**:
   - Queries and inspects DNS records for **DMARC** (`p=none`, `quarantine`, `reject`) and **SPF** (`-all`, `~all`, `?all`).
   - Flags domain spoofability and direct email impersonation risk.
   - Detects SaaS and Identity Provider footprints (Microsoft 365, Google Workspace, Okta, Jira, Slack, VPN endpoints).
   - Infers corporate email naming schemes (`{first}.{last}`, `{f}{last}`, etc.).

2. **Human Attack Surface Modeling**:
   - Deconstructs organizations across high-value departments (Executive & C-Suite, Finance, IT & DevOps, HR & Recruiting, Sales/Support).
   - Correlates privilege levels with public OSINT visibility.

3. **Social Engineering Risk Index (SERI)**:
   - Evaluates composite organizational vulnerability on a 0 - 100 scale:
     $$\text{SERI} = 0.35 \times \text{DomainSpoofRisk} + 0.40 \times \text{HumanAttackSurfaceRisk} + 0.25 \times \text{TechStackRisk}$$
   - Maps scores into clear risk tiers: `LOW` (0-30), `MODERATE` (31-60), `ELEVATED` (61-80), `CRITICAL` (81-100).

4. **AI Behavioral & Pretexting Engine**:
   - Analyzes psychological vulnerability triggers (Authority Bias, Artificial Urgency, Job Obligation, Familiarity).
   - Maps plausible attack scenarios (BEC, illicit OAuth consent grants, MFA push bombing, weaponized resume attachments) and highlights cognitive blindspots and defensive indicators.
   - Dual-engine architecture: Built-in deterministic expert engine + optional Gemini 1.5 Flash generative reasoning.

5. **CISO Remediation & Training Playbooks**:
   - Prioritized technical controls (DMARC `p=reject` roadmap, FIDO2/WebAuthn passkey enforcement, external email banners).
   - Procedural governance (Out-of-Band dual authorization for wire transfers, HR ATS document sandbox).
   - Department-specific micro-learning drills and 30-60-90 day implementation roadmaps.

6. **Executive Reporting**:
   - Generates publication-ready Markdown briefs and standalone styled HTML reports.

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
