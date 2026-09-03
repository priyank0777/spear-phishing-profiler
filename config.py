"""
Configuration settings, risk scoring weights, and threat matrices
for Spear-Phishing & Social Engineering Profiler.
"""

import os
from pathlib import Path

# Paths
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
REPORTS_DIR = BASE_DIR / "reports"

# Social Engineering Risk Index (SERI) Component Weights (Total = 1.0)
SERI_WEIGHT_DOMAIN_DEFENSE = 0.35     # Email spoofability & DNS posture
SERI_WEIGHT_DEPT_EXPOSURE = 0.40      # Human attack surface & privilege level
SERI_WEIGHT_TECH_STACK = 0.25         # Exposed SaaS & authentication vectors

# Risk Severity Tiers
RISK_TIERS = {
    "LOW": {"range": (0, 30), "color": "#28a745", "badge": "🛡️ LOW RISK", "desc": "Robust defenses, low public exposure."},
    "MODERATE": {"range": (31, 60), "color": "#ffc107", "badge": "⚠️ MODERATE RISK", "desc": "Partial defenses or moderate human attack surface."},
    "ELEVATED": {"range": (61, 80), "color": "#fd7e14", "badge": "🚨 ELEVATED RISK", "desc": "Weak email controls or high-value targeted personnel."},
    "CRITICAL": {"range": (81, 100), "color": "#dc3545", "badge": "🔥 CRITICAL RISK", "desc": "Severe spoofability, unprotected high-value departments."}
}

# DMARC Policy Threat Scoring (Higher = Worse)
DMARC_POLICY_RISK = {
    "missing": 100,      # No DMARC record found; completely spoofable
    "none": 85,          # p=none (monitoring only; spoofs still land in inbox)
    "quarantine": 40,    # p=quarantine (spoofs routed to spam folder)
    "reject": 10         # p=reject (spoofs actively dropped by receiving MTA)
}

# SPF Record Threat Scoring
SPF_QUALIFIER_RISK = {
    "missing": 90,       # No SPF record
    "neutral": 75,       # ?all (permits anything with neutral score)
    "softfail": 45,      # ~all (softfail, commonly delivered with warning)
    "hardfail": 15       # -all (strict hardfail)
}

# Department Baseline Susceptibility Factors (0 - 100)
DEPARTMENT_PROFILES = {
    "Finance & Accounting": {
        "baseline_risk": 92,
        "primary_threats": ["Business Email Compromise (BEC)", "Fake Supplier Invoices", "Payroll Diversion", "Urgent Wire Transfer Requests"],
        "psychological_levers": ["Authority (CEO/CFO Impersonation)", "Urgency", "Fear of Contract Loss"],
        "criticality": "CRITICAL"
    },
    "Executive & C-Suite": {
        "baseline_risk": 88,
        "primary_threats": ["Whaling", "Corporate Espionage", "Prestige Impersonation", "Board Portal Phishing"],
        "psychological_levers": ["Prestige / Flattery", "Urgency", "High-Stakes Confidentiality"],
        "criticality": "CRITICAL"
    },
    "IT & DevOps / Security": {
        "baseline_risk": 85,
        "primary_threats": ["OAuth Consent Phishing (Illicit Grants)", "MFA Push Fatigue", "Cloud Admin Credential Harvester", "Fake Security Alerts"],
        "psychological_levers": ["Technical Authority", "Emergency Infrastructure Outage", "System Decommission Warning"],
        "criticality": "HIGH"
    },
    "Human Resources & Recruiting": {
        "baseline_risk": 78,
        "primary_threats": ["Weaponized Resume / Portfolio Documents", "Fake Job Applicant Links", "Employee Grievance Impersonation"],
        "psychological_levers": ["Curiosity", "Job Obligation", "Compliance Pressure"],
        "criticality": "HIGH"
    },
    "Customer Support & Sales": {
        "baseline_risk": 68,
        "primary_threats": ["Ticket System Credential Phishing", "Malicious Inbound Lead Attachments", "Gift Card / Reward Scams"],
        "psychological_levers": ["Customer Satisfaction Pressure", "Greed / Commission Opportunity", "Urgency"],
        "criticality": "MEDIUM"
    },
    "Legal & Compliance": {
        "baseline_risk": 62,
        "primary_threats": ["Fake Subpoenas / Court Notices", "Copyright Infringement DMCA Notices", "Regulatory Audit Pretexts"],
        "psychological_levers": ["Legal Intimidation", "Fear of Penalties", "Regulatory Deadlines"],
        "criticality": "MEDIUM"
    },
    "General / Operations": {
        "baseline_risk": 50,
        "primary_threats": ["Fake HR Benefits Updates", "Package Delivery Notifications", "Password Expiry Notices"],
        "psychological_levers": ["Convenience", "Fear of Service Interruption"],
        "criticality": "LOW"
    }
}

# Known SaaS & Tech Stack Footprints to Detect
TECH_STACK_SIGNATURES = {
    "Microsoft 365": {
        "dns_indicators": ["outlook.com", "protection.outlook.com", "onmicrosoft.com", "msft"],
        "threat_vector": "Fake Microsoft Login / Shared OneDrive-SharePoint Document Lures",
        "risk_multiplier": 1.25
    },
    "Google Workspace": {
        "dns_indicators": ["google.com", "googlemail.com", "aspmx.l.google.com"],
        "threat_vector": "Google Drive / Docs Shared Folder Phishing & OAuth Consent Grants",
        "risk_multiplier": 1.20
    },
    "Okta / Identity Provider": {
        "dns_indicators": ["okta.com", "oktapreview.com"],
        "threat_vector": "Single Sign-On (SSO) Portal Cloning & Push Notification Spam (MFA Fatigue)",
        "risk_multiplier": 1.35
    },
    "Slack": {
        "dns_indicators": ["slack.com"],
        "threat_vector": "Workspace Join Invite Pretexts & Lateral Phishing via Compromised Accounts",
        "risk_multiplier": 1.15
    },
    "Atlassian / Jira": {
        "dns_indicators": ["atlassian.net", "jira.com"],
        "threat_vector": "Urgent Ticket Escalation & Bug Report Malicious Attachment",
        "risk_multiplier": 1.15
    },
    "Salesforce": {
        "dns_indicators": ["salesforce.com", "force.com"],
        "threat_vector": "Lead Notification & CRM Credential Harvester",
        "risk_multiplier": 1.20
    },
    "Remote Access / VPN": {
        "dns_indicators": ["vpn.", "remote.", "gateway.", "pulse.", "globalprotect."],
        "threat_vector": "Remote Work / IT Gateway Credential Theft & Fake VPN Client Update",
        "risk_multiplier": 1.40
    }
}

# AI Engine Settings
AI_PROVIDER = os.getenv("AI_PROVIDER", "deterministic") # 'deterministic', 'gemini', 'groq'
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
