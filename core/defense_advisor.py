"""
Defense Advisor module: synthesizes technical mitigation roadmaps,
CISO governance policies, and department-tailored human awareness training playbooks.
"""

from typing import Dict, Any, List

class DefenseAdvisor:
    """Generates technical controls and human defense training playbooks."""

    def generate_remediation_roadmap(
        self,
        domain_recon: Dict[str, Any],
        org_model: Dict[str, Any],
        seri_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Creates prioritized mitigation actions across technical, procedural, and human layers."""
        technical_controls = self._generate_technical_controls(domain_recon, seri_results)
        procedural_policies = self._generate_procedural_policies(org_model)
        training_curriculum = self._generate_training_curriculum(org_model)
        timeline = self._generate_implementation_timeline(domain_recon, seri_results)

        return {
            "technical_controls": technical_controls,
            "procedural_policies": procedural_policies,
            "training_curriculum": training_curriculum,
            "implementation_timeline": timeline,
            "executive_priorities": self._extract_top_priorities(technical_controls, procedural_policies)
        }

    def _generate_technical_controls(
        self,
        domain_recon: Dict[str, Any],
        seri_results: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Synthesizes technical controls based on DNS, email, and identity posture."""
        controls = []
        dmarc_pol = domain_recon.get("dmarc", {}).get("policy", "missing")
        spf_qual = domain_recon.get("spf", {}).get("qualifier", "missing")
        tech_names = [t["name"] for t in domain_recon.get("tech_stack", [])]

        # DMARC Enforcement
        if dmarc_pol != "reject":
            controls.append({
                "control": "Enforce DMARC Policy (p=reject)",
                "category": "Email Security & Anti-Spoofing",
                "urgency": "IMMEDIATE (P1)" if dmarc_pol in ["missing", "none"] else "HIGH (P2)",
                "rationale": f"Current policy is '{dmarc_pol}'. Without p=reject, adversaries can forge emails from your domain that reach target inboxes unflagged.",
                "implementation_steps": [
                    "Audit current mail delivery streams using DMARC aggregate reports (rua).",
                    "Align SPF and DKIM for all legitimate sending services (M365, Google, Salesforce, SendGrid).",
                    "Escalate policy: p=none -> p=quarantine (pct=50) -> p=quarantine (pct=100) -> p=reject."
                ]
            })

        # SPF Hardfail
        if spf_qual != "hardfail":
            controls.append({
                "control": "Harden SPF Record to Hardfail (-all)",
                "category": "DNS Hygiene",
                "urgency": "HIGH (P2)",
                "rationale": f"Current SPF qualifier is '{spf_qual}'. Softfail allows unauthorized IPs to deliver email with minor score penalties.",
                "implementation_steps": [
                    "Verify all authorized sender IP ranges and third-party SaaS includes.",
                    "Update DNS TXT record to terminate with '-all' instead of '~all' or '?all'."
                ]
            })

        # Phishing-Resistant MFA (FIDO2 / WebAuthn)
        controls.append({
            "control": "Deploy Phishing-Resistant MFA (FIDO2 / Passkeys)",
            "category": "Identity & Access Management (IAM)",
            "urgency": "IMMEDIATE (P1)",
            "rationale": "Traditional SMS and simple push MFA are easily bypassed by Adversary-in-the-Middle (AitM) reverse proxies (Evilginx) and MFA push bombing.",
            "implementation_steps": [
                "Mandate FIDO2 hardware security keys (YubiKey) or Windows Hello / Touch ID for IT Admins and Executives.",
                "Enable Number Matching and Geolocation Context on mobile push prompts in Microsoft Entra / Okta."
            ]
        })

        # OAuth Consent Grant Restrictions
        if "Microsoft 365" in tech_names or "Google Workspace" in tech_names:
            controls.append({
                "control": "Restrict Third-Party OAuth App Consent",
                "category": "SaaS Cloud Security",
                "urgency": "HIGH (P2)",
                "rationale": "Prevents illicit consent grant phishing where users authorize rogue apps to access email and cloud storage without credentials.",
                "implementation_steps": [
                    "Disable user consent for unverified publishers in Entra ID / Google Workspace Admin.",
                    "Require IT administrator workflow approval for any app requesting Mail.ReadWrite or Files.ReadWrite scopes."
                ]
            })

        # External Sender Banners
        controls.append({
            "control": "Implement Distinct External Email Warning Banners",
            "category": "User Awareness Controls",
            "urgency": "MEDIUM (P3)",
            "rationale": "Visual visual cues on inbound emails break cognitive autopilot when an external sender attempts lookalike impersonation.",
            "implementation_steps": [
                "Configure Exchange Mail Flow Rule / Google Workspace Compliance rule.",
                "Prepend standard highlighted banner: '[CAUTION: EXTERNAL SENDER] Do not click links or input credentials unless verified.'"
            ]
        })

        return controls

    def _generate_procedural_policies(self, org_model: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Synthesizes organizational governance procedures."""
        return [
            {
                "policy_name": "Out-of-Band (OOB) Dual Verification for Wire Transfers",
                "target_departments": ["Finance & Accounting", "Executive & C-Suite"],
                "rule": "Mandate verbal confirmation via a pre-established telephone number (never the number provided in the email/invoice) before executing any wire or ACH change > $5,000.",
                "benefit": "100% effective against pure Business Email Compromise (BEC) and fake invoice rerouting."
            },
            {
                "policy_name": "Applicant Document Isolation & Sandbox Protocol",
                "target_departments": ["Human Resources & Recruiting"],
                "rule": "Recruiters must process incoming portfolios and resumes exclusively through the official Applicant Tracking System (ATS) in cloud preview mode, never downloading unvetted password-protected archives.",
                "benefit": "Eliminates endpoint macro execution and malicious LNK shortcut loader execution."
            },
            {
                "policy_name": "No-Blame Phishing Incident Reporting Incentive",
                "target_departments": ["All Employees"],
                "rule": "Establish a single-click 'Report Suspicious Email' button in Outlook/Gmail and recognize employees who report simulated or real attacks promptly rather than penalizing initial clicks.",
                "benefit": "Reduces Mean Time to Detect (MTTD) from days to minutes through human crowd-sourced telemetry."
            }
        ]

    def _generate_training_curriculum(self, org_model: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Creates department-tailored micro-learning awareness modules."""
        modules = []
        for dept in org_model.get("departments", []):
            name = dept.get("name", "General")
            if "Finance" in name:
                modules.append({
                    "department": name,
                    "module_title": "Combating BEC & High-Stakes Wire Fraud",
                    "focus": "Identifying authority pressure, spotting subtle lookalike sender addresses, and practicing out-of-band supplier verification protocols.",
                    "frequency": "Monthly Micro-Drills (5 mins)"
                })
            elif "Executive" in name:
                modules.append({
                    "department": name,
                    "module_title": "Executive Whaling & Mobile Threat Defense",
                    "focus": "Recognizing prestige lures, navigating mobile email UI traps, and managing executive public travel disclosures.",
                    "frequency": "Quarterly Executive Briefing"
                })
            elif "IT" in name:
                modules.append({
                    "department": name,
                    "module_title": "Phishing-Resistant IAM & OAuth Governance",
                    "focus": "Analyzing AitM reverse proxy indicators, handling MFA fatigue attacks, and auditing OAuth app scopes.",
                    "frequency": "Bi-Monthly Technical Walkthrough"
                })
            elif "HR" in name:
                modules.append({
                    "department": name,
                    "module_title": "Recruiting Attack Surface & Document Safety",
                    "focus": "Identifying obfuscated archives, recognizing fake applicant profiles, and safe handling of external candidate links.",
                    "frequency": "Monthly Micro-Drills"
                })
            else:
                modules.append({
                    "department": name,
                    "module_title": "Everyday Phishing Hygiene & Credential Protection",
                    "focus": "Spotting fake login portals, checking browser address bars, and reporting suspicious emails.",
                    "frequency": "Quarterly Interactive Training"
                })
        return modules

    def _generate_implementation_timeline(
        self,
        domain_recon: Dict[str, Any],
        seri_results: Dict[str, Any]
    ) -> Dict[str, List[str]]:
        """Provides a 30-60-90 day CISO execution timeline."""
        return {
            "Immediate (Days 1 - 7)": [
                "Establish mandatory Out-of-Band (OOB) wire callback policy for Finance.",
                "Audit DNS records and deploy DMARC monitoring (p=none with rua reporting).",
                "Deploy 'External Email' warning banner across all inbound gateways."
            ],
            "Short-Term (Days 8 - 30)": [
                "Escalate DMARC policy to p=quarantine for non-aligned senders.",
                "Enforce Number Matching for MFA push notifications across all users.",
                "Distribute FIDO2 hardware tokens to IT Admins and Executive leadership.",
                "Launch department-specific micro-training drills (Finance & HR)."
            ],
            "Long-Term (Days 31 - 90)": [
                "Enforce strict DMARC p=reject across primary domain and all registered subdomains.",
                "Lock down third-party OAuth app consent in Cloud IdP (Entra / Google).",
                "Implement single-click phishing reporting button in enterprise email client.",
                "Establish continuous threat simulation and human firewall resilience metrics."
            ]
        }

    def _extract_top_priorities(
        self,
        controls: List[Dict[str, Any]],
        policies: List[Dict[str, Any]]
    ) -> List[str]:
        """Extracts top 3 urgent priorities for executive action."""
        priorities = []
        for c in controls:
            if "IMMEDIATE" in c.get("urgency", ""):
                priorities.append(f"{c['control']} ({c['category']})")
        if policies:
            priorities.append(f"{policies[0]['policy_name']}")
        return priorities[:3]
