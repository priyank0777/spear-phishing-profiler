"""
Organization Mapper module: models departments, human attack surface,
role privilege tiers, and public OSINT exposure levels.
"""

import json
from pathlib import Path
from typing import Dict, Any, List, Optional
from config import DATA_DIR, DEPARTMENT_PROFILES

class OrgMapper:
    """Models organizational structure and human attack surface vectors."""

    PRIVILEGE_WEIGHTS = {
        "CRITICAL": 1.0,  # Access to finances, core cloud infra, C-level authority
        "HIGH": 0.8,      # Access to production code, internal employee records
        "MEDIUM": 0.5,    # General employee access, CRM, standard ticket queues
        "LOW": 0.3        # Restricted access, contractors
    }

    EXPOSURE_WEIGHTS = {
        "HIGH": 1.0,      # Highly visible on LinkedIn, conference speakers, public emails
        "MEDIUM": 0.6,    # Moderately visible, directory listings
        "LOW": 0.3        # Stealth internal roles, backend engineers
    }

    def __init__(self):
        self.sample_profiles_path = DATA_DIR / "sample_profiles.json"
        self.sample_profiles = self._load_sample_profiles()

    def _load_sample_profiles(self) -> Dict[str, Any]:
        """Loads bundled demonstration enterprise profiles."""
        if self.sample_profiles_path.exists():
            try:
                with open(self.sample_profiles_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def get_sample_profile(self, profile_key: str) -> Optional[Dict[str, Any]]:
        """Retrieves a specific sample organization profile."""
        return self.sample_profiles.get(profile_key)

    def list_sample_profiles(self) -> List[Dict[str, str]]:
        """Lists available sample profiles with their industry and domain."""
        result = []
        for key, val in self.sample_profiles.items():
            result.append({
                "key": key,
                "name": val.get("name", key),
                "domain": val.get("domain", ""),
                "industry": val.get("industry", ""),
                "employees": str(val.get("employee_count", 0))
            })
        return result

    def build_custom_organization(
        self,
        name: str,
        domain: str,
        industry: str,
        departments_data: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Builds a structured organization model from raw input data."""
        processed_departments = []
        total_headcount = 0

        for dept in departments_data:
            dept_name = dept.get("name", "General / Operations")
            headcount = int(dept.get("headcount", 10))
            privilege = dept.get("privilege_level", "MEDIUM").upper()
            exposure = dept.get("public_exposure", "MEDIUM").upper()
            roles = dept.get("sample_roles", [])
            
            # Retrieve baseline department profile
            dept_info = DEPARTMENT_PROFILES.get(dept_name, DEPARTMENT_PROFILES["General / Operations"])
            
            # Compute department attack surface exposure factor (0 - 100)
            p_val = self.PRIVILEGE_WEIGHTS.get(privilege, 0.5)
            e_val = self.EXPOSURE_WEIGHTS.get(exposure, 0.5)
            
            # Raw vulnerability factor combining baseline threat, privilege, and visibility
            dept_risk_raw = dept_info["baseline_risk"] * (0.6 * p_val + 0.4 * e_val)
            dept_risk_score = min(100.0, max(10.0, round(dept_risk_raw, 1)))

            processed_departments.append({
                "name": dept_name,
                "headcount": headcount,
                "privilege_level": privilege,
                "public_exposure": exposure,
                "sample_roles": roles,
                "baseline_threats": dept_info["primary_threats"],
                "psychological_levers": dept_info["psychological_levers"],
                "dept_risk_score": dept_risk_score,
                "risk_score": dept_risk_score,
                "criticality": dept_info["criticality"]
            })
            total_headcount += headcount

        return {
            "name": name,
            "domain": domain,
            "industry": industry,
            "employee_count": total_headcount,
            "departments": processed_departments
        }

    def generate_default_departments(self) -> List[Dict[str, Any]]:
        """Generates standard baseline departments for rapid analysis."""
        return [
            {
                "name": "Executive & C-Suite",
                "headcount": 6,
                "sample_roles": ["Chief Executive Officer", "Chief Financial Officer"],
                "public_exposure": "HIGH",
                "privilege_level": "CRITICAL"
            },
            {
                "name": "Finance & Accounting",
                "headcount": 15,
                "sample_roles": ["Accounts Payable Specialist", "Senior Controller", "Payroll Manager"],
                "public_exposure": "HIGH",
                "privilege_level": "CRITICAL"
            },
            {
                "name": "IT & DevOps / Security",
                "headcount": 25,
                "sample_roles": ["Cloud Security Engineer", "Systems Administrator", "DevOps Engineer"],
                "public_exposure": "MEDIUM",
                "privilege_level": "CRITICAL"
            },
            {
                "name": "Human Resources & Recruiting",
                "headcount": 12,
                "sample_roles": ["Talent Acquisition Partner", "HR Business Partner"],
                "public_exposure": "HIGH",
                "privilege_level": "MEDIUM"
            },
            {
                "name": "Customer Support & Sales",
                "headcount": 60,
                "sample_roles": ["Customer Success Lead", "Sales Account Executive"],
                "public_exposure": "HIGH",
                "privilege_level": "MEDIUM"
            },
            {
                "name": "Legal & Compliance",
                "headcount": 5,
                "sample_roles": ["Corporate Counsel", "Compliance Analyst"],
                "public_exposure": "MEDIUM",
                "privilege_level": "MEDIUM"
            }
        ]
