"""
AI Profiler module: performs behavioral and psychographic susceptibility analysis,
pretexting vector synthesis, and cognitive trigger modeling.
Supports both built-in deterministic expert reasoning and optional LLM integration.
"""

import os
import json
from typing import Dict, Any, List, Optional
from config import DATA_DIR, GEMINI_API_KEY, GROQ_API_KEY

class AIProfiler:
    """Performs behavioral susceptibility analysis for targeted departments."""

    def __init__(self):
        self.threat_catalog_path = DATA_DIR / "threat_catalog.json"
        self.threat_catalog = self._load_threat_catalog()

    def _load_threat_catalog(self) -> Dict[str, Any]:
        """Loads the pre-compiled social engineering threat vectors and MITRE mappings."""
        if self.threat_catalog_path.exists():
            try:
                with open(self.threat_catalog_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def profile_organization(
        self,
        domain_recon: Dict[str, Any],
        org_model: Dict[str, Any],
        seri_results: Dict[str, Any],
        api_key: Optional[str] = None
    ) -> Dict[str, Any]:
        """Generates deep psychographic profiling and pretexting threat analysis."""
        # Check if LLM API is requested and key available
        active_key = api_key or GEMINI_API_KEY
        if active_key:
            try:
                llm_result = self._generate_with_gemini(domain_recon, org_model, seri_results, active_key)
                if llm_result:
                    return llm_result
            except Exception:
                pass # Fallback cleanly to deterministic engine

        return self._generate_deterministic_profile(domain_recon, org_model, seri_results)

    def _generate_deterministic_profile(
        self,
        domain_recon: Dict[str, Any],
        org_model: Dict[str, Any],
        seri_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generates structured behavioral vulnerability profiles using deterministic rules."""
        department_profiles = []
        domain = domain_recon.get("domain", "target-company.com")
        spoof_level = domain_recon.get("spoof_assessment", {}).get("threat_level", "HIGH")
        tech_names = [t["name"] for t in domain_recon.get("tech_stack", [])]

        for dept in org_model.get("departments", []):
            name = dept.get("name", "Unknown")
            risk_score = dept.get("risk_score", 50.0)
            
            scenarios = self._synthesize_department_scenarios(name, domain, spoof_level, tech_names)
            psych_triggers = self._analyze_psychological_triggers(name)

            department_profiles.append({
                "department": name,
                "headcount": dept.get("headcount", 1),
                "risk_score": risk_score,
                "criticality": dept.get("criticality", "MEDIUM"),
                "cognitive_vulnerabilities": psych_triggers,
                "plausible_scenarios": scenarios,
                "human_firewall_readiness": self._estimate_firewall_readiness(risk_score, spoof_level)
            })

        return {
            "engine_used": "Deterministic Expert AI Engine",
            "organization_name": org_model.get("name", "Target Organization"),
            "domain": domain,
            "department_profiles": department_profiles,
            "executive_takeaway": self._generate_executive_takeaway(seri_results, domain_recon)
        }

    def _synthesize_department_scenarios(
        self,
        dept_name: str,
        domain: str,
        spoof_level: str,
        tech_names: List[str]
    ) -> List[Dict[str, Any]]:
        """Synthesizes plausible defensive scenario briefs tailored to department roles."""
        scenarios = []
        spoof_context = "direct header spoofing" if spoof_level in ["HIGH", "CRITICAL"] else "lookalike typosquatted domain"

        if "Finance" in dept_name:
            scenarios.append({
                "scenario_title": "Urgent Vendor Banking Details Alteration (BEC)",
                "threat_vector": "Business Email Compromise (BEC)",
                "mitre_technique": "T1566.002",
                "attacker_pretext": f"Adversary sends an urgent email via {spoof_context} mimicking a key supplier or CFO, requesting immediate remittance to a new routing number before fiscal close.",
                "psychological_hook": "Authority + High Urgency + Fear of Contract Breach",
                "employee_cognitive_blindspot": "Employees are hesitant to question C-level directives or delay legitimate vendor payments when under deadline pressure.",
                "defensive_indicator": "Discrepancy in Reply-To headers, slight difference in vendor display name, pressure to bypass standard ERP verification."
            })
            scenarios.append({
                "scenario_title": "Payroll Tax & Direct Deposit Re-route",
                "threat_vector": "Phishing for Information (T1598)",
                "mitre_technique": "T1598",
                "attacker_pretext": "Impersonates an executive requesting their W-2 or asking to switch their direct deposit account ahead of the next pay cycle.",
                "psychological_hook": "Authority + Routine Compliance",
                "employee_cognitive_blindspot": "Appears as a routine administrative request where employees assume good faith.",
                "defensive_indicator": "Request originates from an external or personal email address requesting payroll changes without portal login."
            })

        elif "Executive" in dept_name:
            scenarios.append({
                "scenario_title": "Whaling / Board of Directors Confidential Portal",
                "threat_vector": "Spearphishing Link (T1566.002)",
                "mitre_technique": "T1566.002",
                "attacker_pretext": "Fake notification from 'Boardvantage' or corporate legal counsel requesting immediate review of an NDA or M&A briefing document.",
                "psychological_hook": "Prestige + Extreme Confidentiality + FOMO",
                "employee_cognitive_blindspot": "Executives often operate on mobile devices while traveling, where full URL bars and certificate details are truncated.",
                "defensive_indicator": "External domain masquerading as board portal, shortened or redirecting URL parameters."
            })

        elif "IT" in dept_name or "DevOps" in dept_name:
            if "Okta / Identity Provider" in tech_names:
                scenarios.append({
                    "scenario_title": "Identity Provider (Okta) Session Revocation & MFA Fatigue",
                    "threat_vector": "Valid Accounts / MFA Bombing (T1078)",
                    "mitre_technique": "T1078",
                    "attacker_pretext": "Attacker triggers multiple push notifications at 2:00 AM, followed by a simulated IT Slack message: 'High priority: re-verify Okta device token to prevent service outage'.",
                    "psychological_hook": "Cognitive Fatigue + Emergency Infrastructure Duty",
                    "employee_cognitive_blindspot": "Engineers are accustomed to responding to nighttime on-call pages and may approve push prompts to stop alerts.",
                    "defensive_indicator": "Unprompted push notifications, unfamiliar geolocation / IP on sign-in prompt."
                })
            else:
                scenarios.append({
                    "scenario_title": "OAuth App Consent Phishing (Illicit Cloud Grant)",
                    "threat_vector": "Spearphishing via Service (T1566.003)",
                    "mitre_technique": "T1566.003",
                    "attacker_pretext": "A request to authorize a developer tool or CI/CD monitoring integration that silently requests offline access and directory permissions.",
                    "psychological_hook": "Convenience + Technical Familiarity",
                    "employee_cognitive_blindspot": "Users assume that because the login screen is a legitimate Microsoft/Google OAuth dialog, the application itself must be secure.",
                    "defensive_indicator": "Third-party publisher unverified, excessive scopes requested (Mail.ReadWrite, Files.ReadWrite.All)."
                })

        elif "HR" in dept_name or "Recruiting" in dept_name:
            scenarios.append({
                "scenario_title": "Weaponized Resume / Portfolio Macro Attachment",
                "threat_vector": "Spearphishing Attachment (T1566.001)",
                "mitre_technique": "T1566.001",
                "attacker_pretext": "Applicant submits a PDF or password-protected ZIP claiming to be a senior architect portfolio, asking HR to open it or click an embedded cloud link.",
                "psychological_hook": "Job Obligation + Curiosity + Fear of Losing Top Candidate",
                "employee_cognitive_blindspot": "HR roles are measured on candidate response speed and naturally open dozens of external documents daily.",
                "defensive_indicator": "Password-protected archives, macros requested to enable editing, executable disguised with double extension (.pdf.exe)."
            })

        else: # Support / Sales / General
            scenarios.append({
                "scenario_title": "Cloud Storage Collaboration Link (OneDrive/SharePoint)",
                "threat_vector": "Spearphishing Link (T1566.002)",
                "mitre_technique": "T1566.002",
                "attacker_pretext": f"Notification claiming a client shared a proposal document via Microsoft 365 / Google Drive, requiring login to view.",
                "psychological_hook": "Familiarity + Business Opportunity",
                "employee_cognitive_blindspot": "Employees frequently click collaboration links without verifying the exact destination domain.",
                "defensive_indicator": "Landing page prompts for re-authentication on a domain other than the official login portal."
            })

        return scenarios

    def _analyze_psychological_triggers(self, dept_name: str) -> List[Dict[str, str]]:
        """Maps department responsibilities to cognitive manipulation triggers."""
        triggers = []
        if "Finance" in dept_name:
            triggers.append({"trigger": "Authority Bias", "vulnerability": "High tendency to comply with instructions appearing from the CEO or CFO without challenge."})
            triggers.append({"trigger": "Artificial Time Constraint", "vulnerability": "Strict deadlines (wire cutoff at 4:30 PM) induce panic and suppress analytical verification."})
        elif "Executive" in dept_name:
            triggers.append({"trigger": "Ego & Prestige", "vulnerability": "Appeals to executive stature (exclusive invitations, confidential board matters)."})
            triggers.append({"trigger": "Mobile Screen Truncation", "vulnerability": "Reviewing communications quickly on mobile devices where sender certificates are hidden."})
        elif "IT" in dept_name:
            triggers.append({"trigger": "System Outage Aversion", "vulnerability": "Engineers instinctively want to resolve broken builds, expired certificates, or downed services quickly."})
            triggers.append({"trigger": "Technological Familiarity", "vulnerability": "Lower suspicion towards legitimate-looking developer tools, APIs, and OAuth dialogs."})
        elif "HR" in dept_name:
            triggers.append({"trigger": "Inherent Inbound Trust", "vulnerability": "Job role explicitly requires opening inbound communications and attachments from total strangers."})
            triggers.append({"trigger": "Candidate Empathy", "vulnerability": "Reluctance to reject an applicant who claims their document format is having technical issues."})
        else:
            triggers.append({"trigger": "Routine Compliance", "vulnerability": "Habitual compliance with internal IT and benefits announcements."})
            triggers.append({"trigger": "Fear of Disciplinary Action", "vulnerability": "Notices threatening account suspension for non-completion of compliance courses."})
        return triggers

    def _estimate_firewall_readiness(self, risk_score: float, spoof_level: str) -> Dict[str, str]:
        """Estimates the human resilience level and provides readiness rating."""
        if risk_score >= 80 or spoof_level in ["HIGH", "CRITICAL"]:
            return {"rating": "VULNERABLE", "color": "#dc3545", "recommendation": "Urgent simulated training drills and strict secondary verification procedures needed."}
        elif risk_score >= 60:
            return {"rating": "MODERATE EXPOSURE", "color": "#fd7e14", "recommendation": "Targeted micro-learning modules on department-specific pretexting required."}
        else:
            return {"rating": "ACCEPTABLE", "color": "#28a745", "recommendation": "Maintain quarterly awareness testing and continuous reporting incentives."}

    def _generate_executive_takeaway(self, seri_results: Dict[str, Any], domain_recon: Dict[str, Any]) -> str:
        """Generates concise executive takeaway for C-level leadership."""
        score = seri_results.get("seri_score", 50.0)
        tier = seri_results.get("risk_tier", "MODERATE")
        dmarc_pol = domain_recon.get("dmarc", {}).get("policy", "missing")
        
        takeaway = f"The organization registers a Social Engineering Risk Index (SERI) of {score}/100, placing it in the {tier} tier. "
        if dmarc_pol in ["missing", "none"]:
            takeaway += f"The absence of an enforced DMARC policy (currently '{dmarc_pol}') provides adversaries with an open vector to spoof official company email addresses directly into employee and partner inboxes without triggering security warnings. "
        takeaway += "Departmental attack surface analysis reveals that executive and finance personnel represent the highest financial blast radius, while IT and HR departments serve as prime initial-access pivot vectors."
        return takeaway

    def _generate_with_gemini(
        self,
        domain_recon: Dict[str, Any],
        org_model: Dict[str, Any],
        seri_results: Dict[str, Any],
        api_key: str
    ) -> Optional[Dict[str, Any]]:
        """Optional Gemini API integration for real-time generative threat reasoning."""
        import requests
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
        prompt = f"""
        Act as an elite Red Team and Defensive Social Engineering Specialist.
        Analyze this organization profile:
        Organization: {org_model.get('name')}
        Domain: {domain_recon.get('domain')}
        DMARC: {domain_recon.get('dmarc', {}).get('policy')}
        SPF: {domain_recon.get('spf', {}).get('qualifier')}
        SERI Score: {seri_results.get('seri_score')}/100 ({seri_results.get('risk_tier')})
        Departments: {[d['name'] for d in org_model.get('departments', [])]}

        Generate:
        1. Executive summary of human attack surface vulnerabilities.
        2. Department-specific psychological triggers (Authority, Urgency, etc.).
        3. Plausible pretexting scenarios for top 3 departments.
        Return as valid JSON with keys: executive_takeaway, department_profiles (list).
        """
        payload = {"contents": [{"parts": [{"text": prompt}]}]}
        response = requests.post(url, json=payload, timeout=8)
        if response.status_code == 200:
            data = response.json()
            raw_text = data["candidates"][0]["content"]["parts"][0]["text"]
            # Clean markdown code blocks if any
            clean_text = raw_text.replace("```json", "").replace("```", "").strip()
            parsed = json.loads(clean_text)
            parsed["engine_used"] = "Gemini 1.5 Flash AI Engine"
            parsed["domain"] = domain_recon.get("domain")
            return parsed
        return None
