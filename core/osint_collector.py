"""
OSINT Collector module: gathers domain DNS posture, MX/SPF/DMARC records,
email spoofability ratings, and SaaS technology footprints.
"""

import re
import socket
from typing import Dict, Any, List, Optional
import dns.resolver
from config import TECH_STACK_SIGNATURES, DMARC_POLICY_RISK, SPF_QUALIFIER_RISK

class OSINTCollector:
    """Gathers open-source reconnaissance data on an organization's domain."""

    def __init__(self, timeout: float = 4.0):
        self.resolver = dns.resolver.Resolver()
        self.resolver.lifetime = timeout
        self.resolver.timeout = timeout

    def inspect_domain(self, domain: str) -> Dict[str, Any]:
        """Performs comprehensive passive DNS and email defense posture analysis."""
        clean_domain = domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
        
        mx_data = self._check_mx(clean_domain)
        spf_data = self._check_spf(clean_domain)
        dmarc_data = self._check_dmarc(clean_domain)
        tech_stack = self._detect_tech_stack(clean_domain, mx_data.get("hosts", []), spf_data.get("raw", ""))
        spoof_assessment = self._assess_spoofability(dmarc_data, spf_data)
        
        return {
            "domain": clean_domain,
            "mx_records": mx_data,
            "spf": spf_data,
            "dmarc": dmarc_data,
            "tech_stack": tech_stack,
            "spoof_assessment": spoof_assessment,
            "inferred_email_patterns": self._infer_email_patterns(clean_domain)
        }

    def _check_mx(self, domain: str) -> Dict[str, Any]:
        """Queries MX (Mail Exchange) records."""
        try:
            answers = self.resolver.resolve(domain, "MX")
            hosts = [str(r.exchange).rstrip(".").lower() for r in answers]
            return {
                "status": "found",
                "hosts": hosts,
                "count": len(hosts),
                "is_secure": len(hosts) > 0
            }
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout, Exception):
            return {
                "status": "missing_or_unreachable",
                "hosts": [],
                "count": 0,
                "is_secure": False
            }

    def _check_spf(self, domain: str) -> Dict[str, Any]:
        """Queries and evaluates SPF (Sender Policy Framework) TXT records."""
        try:
            answers = self.resolver.resolve(domain, "TXT")
            for rdata in answers:
                txt_record = "".join([s.decode("utf-8", errors="ignore") for s in rdata.strings])
                if txt_record.startswith("v=spf1"):
                    qualifier = "neutral"
                    if "-all" in txt_record:
                        qualifier = "hardfail"
                    elif "~all" in txt_record:
                        qualifier = "softfail"
                    elif "?all" in txt_record:
                        qualifier = "neutral"
                    elif "+all" in txt_record:
                        qualifier = "pass"
                    
                    return {
                        "status": "configured",
                        "raw": txt_record,
                        "qualifier": qualifier,
                        "risk_score": SPF_QUALIFIER_RISK.get(qualifier, 60),
                        "description": self._describe_spf_qualifier(qualifier)
                    }
            return {
                "status": "missing",
                "raw": "",
                "qualifier": "missing",
                "risk_score": SPF_QUALIFIER_RISK["missing"],
                "description": "No valid SPF record found. Anyone can claim to send emails from your IP ranges."
            }
        except Exception:
            return {
                "status": "missing",
                "raw": "",
                "qualifier": "missing",
                "risk_score": SPF_QUALIFIER_RISK["missing"],
                "description": "No valid SPF record found or lookup timed out."
            }

    def _check_dmarc(self, domain: str) -> Dict[str, Any]:
        """Queries DMARC record at _dmarc.<domain>."""
        dmarc_domain = f"_dmarc.{domain}"
        try:
            answers = self.resolver.resolve(dmarc_domain, "TXT")
            for rdata in answers:
                txt_record = "".join([s.decode("utf-8", errors="ignore") for s in rdata.strings])
                if "v=dmarc1" in txt_record.lower():
                    policy_match = re.search(r"p=([a-zA-Z]+)", txt_record)
                    policy = policy_match.group(1).lower() if policy_match else "none"
                    rua_match = re.search(r"rua=([^;]+)", txt_record)
                    rua = rua_match.group(1) if rua_match else None
                    
                    return {
                        "status": "configured",
                        "policy": policy,
                        "raw": txt_record,
                        "rua": rua,
                        "risk_score": DMARC_POLICY_RISK.get(policy, 75),
                        "description": self._describe_dmarc_policy(policy)
                    }
            return {
                "status": "missing",
                "policy": "missing",
                "raw": "",
                "rua": None,
                "risk_score": DMARC_POLICY_RISK["missing"],
                "description": "No DMARC record detected. Attackers can forge emails from this domain that land directly in victim inboxes."
            }
        except Exception:
            return {
                "status": "missing",
                "policy": "missing",
                "raw": "",
                "rua": None,
                "risk_score": DMARC_POLICY_RISK["missing"],
                "description": "No DMARC record detected. Highly vulnerable to domain spoofing."
            }

    def _detect_tech_stack(self, domain: str, mx_hosts: List[str], spf_raw: str) -> List[Dict[str, Any]]:
        """Identifies SaaS platforms, mail providers, and authentication gateways."""
        detected = []
        combined_text = (domain + " " + " ".join(mx_hosts) + " " + spf_raw).lower()
        
        for name, info in TECH_STACK_SIGNATURES.items():
            for indicator in info["dns_indicators"]:
                if indicator in combined_text:
                    detected.append({
                        "name": name,
                        "indicator_found": indicator,
                        "threat_vector": info["threat_vector"],
                        "risk_multiplier": info["risk_multiplier"]
                    })
                    break
                    
        # Check remote access / VPN via DNS probing
        vpn_subdomains = ["vpn", "remote", "gateway", "connect"]
        for sub in vpn_subdomains:
            test_host = f"{sub}.{domain}"
            try:
                socket.gethostbyname(test_host)
                if not any(d["name"] == "Remote Access / VPN" for d in detected):
                    detected.append({
                        "name": "Remote Access / VPN",
                        "indicator_found": f"Resolvable host: {test_host}",
                        "threat_vector": TECH_STACK_SIGNATURES["Remote Access / VPN"]["threat_vector"],
                        "risk_multiplier": TECH_STACK_SIGNATURES["Remote Access / VPN"]["risk_multiplier"]
                    })
                break
            except (socket.gaierror, Exception):
                pass

        return detected

    def _assess_spoofability(self, dmarc: Dict[str, Any], spf: Dict[str, Any]) -> Dict[str, Any]:
        """Calculates domain spoofability risk and provides plain English risk assessment."""
        dmarc_pol = dmarc.get("policy", "missing")
        spf_qual = spf.get("qualifier", "missing")
        
        # Calculate domain spoof risk (0 - 100)
        dmarc_weight = 0.70
        spf_weight = 0.30
        
        d_score = dmarc.get("risk_score", 100)
        s_score = spf.get("risk_score", 90)
        
        composite_score = round((d_score * dmarc_weight) + (s_score * spf_weight), 1)
        
        if dmarc_pol in ["missing", "none"]:
            spoofable = True
            level = "HIGH"
            summary = "CRITICAL SPOOFABILITY: Attackers can forge emails with this exact domain in the From header without rejection."
        elif dmarc_pol == "quarantine":
            spoofable = False
            level = "MODERATE"
            summary = "PARTIAL PROTECTION: Spoofed emails may be delivered to the recipient's spam/junk folder."
        else: # reject
            spoofable = False
            level = "LOW"
            summary = "STRONG PROTECTION: Spoofed emails are rejected by receiving mail servers."

        return {
            "spoofable": spoofable,
            "spoof_risk_score": composite_score,
            "threat_level": level,
            "summary": summary
        }

    def _describe_spf_qualifier(self, qual: str) -> str:
        descriptions = {
            "hardfail": "Strict (-all): Receiving servers are instructed to drop unauthorized senders.",
            "softfail": "Softfail (~all): Unauthorized senders are flagged but often still delivered with a warning header.",
            "neutral": "Neutral (?all): No policy enforced; unauthorized mail is accepted.",
            "pass": "Permissive (+all): All servers are allowed to send mail (critical misconfiguration)."
        }
        return descriptions.get(qual, "Unknown SPF qualifier.")

    def _describe_dmarc_policy(self, pol: str) -> str:
        descriptions = {
            "reject": "Enforced (p=reject): Receiving mail servers drop unauthenticated spoofed emails immediately.",
            "quarantine": "Quarantine (p=quarantine): Spoofed emails are directed to spam/junk folders.",
            "none": "Monitoring Only (p=none): Spoofed emails still land in recipient primary inboxes. No active defense."
        }
        return descriptions.get(pol, "No DMARC policy.")

    def _infer_email_patterns(self, domain: str) -> List[Dict[str, str]]:
        """Generates standard corporate email address formats for spear-phishing simulation modeling."""
        return [
            {"format": "{first}.{last}@" + domain, "example": f"john.smith@{domain}", "popularity": "Very Common (~60%)"},
            {"format": "{f}{last}@" + domain, "example": f"jsmith@{domain}", "popularity": "Common (~25%)"},
            {"format": "{first}_{last}@" + domain, "example": f"john_smith@{domain}", "popularity": "Occasional (~10%)"},
            {"format": "{first}@" + domain, "example": f"john@{domain}", "popularity": "Startups (~5%)"}
        ]
