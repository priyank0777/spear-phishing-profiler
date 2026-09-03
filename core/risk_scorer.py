"""
Risk Scorer module: calculates the Social Engineering Risk Index (SERI),
department vulnerability heatmaps, and composite risk tiering.
"""

from typing import Dict, Any, List
from config import (
    SERI_WEIGHT_DOMAIN_DEFENSE,
    SERI_WEIGHT_DEPT_EXPOSURE,
    SERI_WEIGHT_TECH_STACK,
    RISK_TIERS
)

class RiskScorer:
    """Calculates the composite Social Engineering Risk Index (SERI)."""

    def calculate_seri(
        self,
        domain_recon: Dict[str, Any],
        organization_model: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Calculates comprehensive SERI score and risk breakdown."""
        # 1. Domain Spoofability Score (0 - 100)
        domain_spoof_score = domain_recon.get("spoof_assessment", {}).get("spoof_risk_score", 70.0)

        # 2. Human Attack Surface & Department Exposure Score (0 - 100)
        dept_score, dept_breakdown = self._compute_department_risk(organization_model.get("departments", []))

        # 3. Tech Stack & SaaS Risk Score (0 - 100)
        tech_score, tech_breakdown = self._compute_tech_stack_risk(domain_recon.get("tech_stack", []))

        # 4. Composite SERI Score (Weighted sum)
        raw_seri = (
            (domain_spoof_score * SERI_WEIGHT_DOMAIN_DEFENSE) +
            (dept_score * SERI_WEIGHT_DEPT_EXPOSURE) +
            (tech_score * SERI_WEIGHT_TECH_STACK)
        )
        final_seri = round(min(100.0, max(0.0, raw_seri)), 1)

        # 5. Determine Risk Tier
        risk_tier_info = self._get_risk_tier(final_seri)

        # 6. Identify Top Vulnerability Drivers
        top_drivers = self._identify_top_drivers(
            domain_spoof_score,
            dept_score,
            tech_score,
            domain_recon,
            dept_breakdown
        )

        return {
            "seri_score": final_seri,
            "risk_tier": risk_tier_info["tier"],
            "badge": risk_tier_info["badge"],
            "color": risk_tier_info["color"],
            "description": risk_tier_info["desc"],
            "component_scores": {
                "domain_spoof_risk": {
                    "score": round(domain_spoof_score, 1),
                    "weight": SERI_WEIGHT_DOMAIN_DEFENSE,
                    "weighted_contribution": round(domain_spoof_score * SERI_WEIGHT_DOMAIN_DEFENSE, 1)
                },
                "human_attack_surface_risk": {
                    "score": round(dept_score, 1),
                    "weight": SERI_WEIGHT_DEPT_EXPOSURE,
                    "weighted_contribution": round(dept_score * SERI_WEIGHT_DEPT_EXPOSURE, 1)
                },
                "tech_stack_exposure_risk": {
                    "score": round(tech_score, 1),
                    "weight": SERI_WEIGHT_TECH_STACK,
                    "weighted_contribution": round(tech_score * SERI_WEIGHT_TECH_STACK, 1)
                }
            },
            "top_drivers": top_drivers,
            "department_rankings": dept_breakdown,
            "tech_stack_rankings": tech_breakdown
        }

    def _compute_department_risk(self, departments: List[Dict[str, Any]]) -> (float, List[Dict[str, Any]]):
        """Computes weighted human attack surface exposure based on department headcount and criticality."""
        if not departments:
            return 50.0, []

        total_weighted_points = 0.0
        total_weight = 0.0
        ranked_depts = []

        for dept in departments:
            name = dept.get("name", "Unknown")
            headcount = max(1, dept.get("headcount", 1))
            score = dept.get("dept_risk_score", 50.0)
            criticality = dept.get("criticality", "MEDIUM")

            # Weight by headcount with diminishing returns (log scale influence)
            weight = 1.0 + (headcount ** 0.5)
            if criticality == "CRITICAL":
                weight *= 1.5
            elif criticality == "HIGH":
                weight *= 1.25

            total_weighted_points += (score * weight)
            total_weight += weight

            ranked_depts.append({
                "name": name,
                "headcount": headcount,
                "risk_score": score,
                "criticality": criticality,
                "privilege_level": dept.get("privilege_level", "MEDIUM"),
                "public_exposure": dept.get("public_exposure", "MEDIUM"),
                "primary_threats": dept.get("baseline_threats", []),
                "psychological_levers": dept.get("psychological_levers", [])
            })

        # Sort descending by risk score
        ranked_depts.sort(key=lambda x: x["risk_score"], reverse=True)
        avg_score = total_weighted_points / total_weight if total_weight > 0 else 50.0
        return round(avg_score, 1), ranked_depts

    def _compute_tech_stack_risk(self, tech_stack: List[Dict[str, Any]]) -> (float, List[Dict[str, Any]]):
        """Computes risk factor introduced by public SaaS platforms and identity providers."""
        if not tech_stack:
            return 35.0, []

        base_score = 40.0
        accumulated_risk = 0.0
        ranked_tech = []

        for item in tech_stack:
            name = item.get("name", "Unknown")
            mult = item.get("risk_multiplier", 1.1)
            threat = item.get("threat_vector", "General Credential Lures")
            
            # Risk points based on multiplier
            risk_points = round((mult - 1.0) * 100, 1)
            accumulated_risk += risk_points

            ranked_tech.append({
                "name": name,
                "risk_points": risk_points,
                "threat_vector": threat
            })

        total_tech_score = min(100.0, base_score + accumulated_risk)
        ranked_tech.sort(key=lambda x: x["risk_points"], reverse=True)
        return round(total_tech_score, 1), ranked_tech

    def _get_risk_tier(self, score: float) -> Dict[str, Any]:
        """Maps numerical SERI score to descriptive tier."""
        for tier, details in RISK_TIERS.items():
            low, high = details["range"]
            if low <= score <= high:
                return {
                    "tier": tier,
                    "color": details["color"],
                    "badge": details["badge"],
                    "desc": details["desc"]
                }
        return {
            "tier": "CRITICAL",
            "color": "#dc3545",
            "badge": "🔥 CRITICAL RISK",
            "desc": "Severe enterprise exposure requiring immediate remediation."
        }

    def _identify_top_drivers(
        self,
        domain_score: float,
        dept_score: float,
        tech_score: float,
        domain_recon: Dict[str, Any],
        dept_breakdown: List[Dict[str, Any]]
    ) -> List[str]:
        """Identifies specific reasons why the organization is at risk."""
        drivers = []
        dmarc_pol = domain_recon.get("dmarc", {}).get("policy", "missing")
        spf_qual = domain_recon.get("spf", {}).get("qualifier", "missing")

        if dmarc_pol in ["missing", "none"]:
            drivers.append(f"Domain Spoofability: DMARC policy is '{dmarc_pol}' (allows direct sender spoofing).")
        
        if spf_qual in ["missing", "neutral"]:
            drivers.append(f"Insecure SPF Record: SPF qualifier is '{spf_qual}' (insufficient unauthorized sender filtering).")

        if dept_breakdown:
            top_dept = dept_breakdown[0]
            if top_dept["risk_score"] >= 80:
                drivers.append(f"High-Value Department Exposure: '{top_dept['name']}' has high privilege and public visibility.")

        tech_names = [t["name"] for t in domain_recon.get("tech_stack", [])]
        if "Okta / Identity Provider" in tech_names:
            drivers.append("Identity Provider Exposure: Public Okta presence creates high susceptibility to MFA Fatigue and SSO portal cloning.")
        elif "Microsoft 365" in tech_names:
            drivers.append("Collaboration Footprint: Microsoft 365 tenant invites OneDrive/SharePoint shared document spear-phishing lures.")

        if not drivers:
            drivers.append("Baseline hygiene maintained; monitor employee public disclosures.")

        return drivers
