"""
Automated unit and integration test suite for Spear-Phising & Social Engineering Profiler.
"""

import unittest
import sys
from pathlib import Path

# Ensure project root is in python path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from core.osint_collector import OSINTCollector
from core.org_mapper import OrgMapper
from core.risk_scorer import RiskScorer
from core.ai_profiler import AIProfiler
from core.defense_advisor import DefenseAdvisor
from reports.report_generator import ReportGenerator

class TestProfilerPipeline(unittest.TestCase):
    """Verifies end-to-end functionality of all profiling modules."""

    @classmethod
    def setUpClass(cls):
        cls.collector = OSINTCollector()
        cls.mapper = OrgMapper()
        cls.scorer = RiskScorer()
        cls.profiler = AIProfiler()
        cls.advisor = DefenseAdvisor()
        cls.reporter = ReportGenerator()

    def test_sample_profiles_loaded(self):
        """Verify bundled sample organizations are available."""
        samples = self.mapper.list_sample_profiles()
        self.assertGreaterEqual(len(samples), 3, "Expected at least 3 benchmark enterprise profiles.")
        keys = [s["key"] for s in samples]
        self.assertIn("ApexFintech", keys)
        self.assertIn("CloudScaleAI", keys)
        self.assertIn("BioCareHealth", keys)

    def test_spoofability_assessment(self):
        """Verify DMARC and SPF risk scoring logic."""
        # Case A: Missing DMARC and softfail SPF -> High spoof risk
        mock_dmarc = {"policy": "missing", "risk_score": 100}
        mock_spf = {"qualifier": "softfail", "risk_score": 45}
        result = self.collector._assess_spoofability(mock_dmarc, mock_spf)
        self.assertTrue(result["spoofable"])
        self.assertGreaterEqual(result["spoof_risk_score"], 80.0)
        self.assertEqual(result["threat_level"], "HIGH")

        # Case B: Strict reject DMARC and hardfail SPF -> Low spoof risk
        mock_dmarc_secure = {"policy": "reject", "risk_score": 10}
        mock_spf_secure = {"qualifier": "hardfail", "risk_score": 15}
        result_sec = self.collector._assess_spoofability(mock_dmarc_secure, mock_spf_secure)
        self.assertFalse(result_sec["spoofable"])
        self.assertLessEqual(result_sec["spoof_risk_score"], 20.0)
        self.assertEqual(result_sec["threat_level"], "LOW")

    def test_custom_organization_building(self):
        """Verify organization attack surface model synthesis."""
        dept_input = [
            {"name": "Finance & Accounting", "headcount": 10, "privilege_level": "CRITICAL", "public_exposure": "HIGH"},
            {"name": "IT & DevOps / Security", "headcount": 20, "privilege_level": "CRITICAL", "public_exposure": "MEDIUM"}
        ]
        org = self.mapper.build_custom_organization("TestCorp", "testcorp.com", "FinTech", dept_input)
        self.assertEqual(org["name"], "TestCorp")
        self.assertEqual(org["employee_count"], 30)
        self.assertEqual(len(org["departments"]), 2)
        # Verify risk score calculated
        self.assertIn("dept_risk_score", org["departments"][0])
        self.assertGreater(org["departments"][0]["dept_risk_score"], 0)

    def test_seri_calculation_and_tiering(self):
        """Verify composite Social Engineering Risk Index calculation."""
        sample = self.mapper.get_sample_profile("ApexFintech")
        org = self.mapper.build_custom_organization(
            sample["name"], sample["domain"], sample["industry"], sample["departments"]
        )
        mock_recon = {
            "domain": sample["domain"],
            "dmarc": {"policy": "none", "risk_score": 85},
            "spf": {"qualifier": "softfail", "risk_score": 45},
            "tech_stack": [{"name": "Microsoft 365", "risk_multiplier": 1.25, "threat_vector": "Credential Lure"}],
            "spoof_assessment": {"spoof_risk_score": 85.0, "threat_level": "HIGH"}
        }

        seri = self.scorer.calculate_seri(mock_recon, org)
        self.assertIsInstance(seri["seri_score"], float)
        self.assertTrue(0.0 <= seri["seri_score"] <= 100.0)
        self.assertIn(seri["risk_tier"], ["LOW", "MODERATE", "ELEVATED", "CRITICAL"])
        self.assertGreater(len(seri["top_drivers"]), 0)

    def test_ai_profiler_deterministic_scenarios(self):
        """Verify psychological vulnerability triggers and pretexting scenarios."""
        sample = self.mapper.get_sample_profile("ApexFintech")
        org = self.mapper.build_custom_organization(
            sample["name"], sample["domain"], sample["industry"], sample["departments"]
        )
        mock_recon = {
            "domain": sample["domain"],
            "dmarc": {"policy": "none"},
            "spf": {"qualifier": "softfail"},
            "tech_stack": [{"name": "Microsoft 365", "risk_multiplier": 1.25}],
            "spoof_assessment": {"threat_level": "HIGH"}
        }
        seri = self.scorer.calculate_seri(mock_recon, org)
        ai_res = self.profiler.profile_organization(mock_recon, org, seri)

        self.assertIn("department_profiles", ai_res)
        self.assertGreater(len(ai_res["department_profiles"]), 0)
        
        # Check first department has scenarios
        first_dept = ai_res["department_profiles"][0]
        self.assertIn("cognitive_vulnerabilities", first_dept)
        self.assertIn("plausible_scenarios", first_dept)
        self.assertGreater(len(first_dept["plausible_scenarios"]), 0)

    def test_defense_advisor_playbooks(self):
        """Verify technical countermeasure generation and remediation timeline."""
        sample = self.mapper.get_sample_profile("ApexFintech")
        org = self.mapper.build_custom_organization(
            sample["name"], sample["domain"], sample["industry"], sample["departments"]
        )
        mock_recon = {
            "domain": sample["domain"],
            "dmarc": {"policy": "none"},
            "spf": {"qualifier": "softfail"},
            "tech_stack": [{"name": "Microsoft 365", "risk_multiplier": 1.25}],
            "spoof_assessment": {"threat_level": "HIGH"}
        }
        seri = self.scorer.calculate_seri(mock_recon, org)
        plan = self.advisor.generate_remediation_roadmap(mock_recon, org, seri)

        self.assertIn("technical_controls", plan)
        self.assertIn("procedural_policies", plan)
        self.assertIn("implementation_timeline", plan)
        self.assertIn("executive_priorities", plan)
        self.assertGreater(len(plan["technical_controls"]), 0)

    def test_report_generation(self):
        """Verify Markdown and HTML generation formats."""
        sample = self.mapper.get_sample_profile("ApexFintech")
        org = self.mapper.build_custom_organization(
            sample["name"], sample["domain"], sample["industry"], sample["departments"]
        )
        mock_recon = {
            "domain": sample["domain"],
            "dmarc": {"policy": "none", "description": "Monitoring only"},
            "spf": {"qualifier": "softfail", "description": "Softfail"},
            "tech_stack": [{"name": "Microsoft 365", "indicator_found": "outlook.com", "threat_vector": "Lure"}],
            "spoof_assessment": {"spoof_risk_score": 85.0, "threat_level": "HIGH", "summary": "High risk"}
        }
        seri = self.scorer.calculate_seri(mock_recon, org)
        ai_res = self.profiler.profile_organization(mock_recon, org, seri)
        plan = self.advisor.generate_remediation_roadmap(mock_recon, org, seri)

        md = self.reporter.generate_markdown_report(mock_recon, org, seri, ai_res, plan)
        html = self.reporter.generate_html_report(mock_recon, org, seri, ai_res, plan)

        self.assertIn("# 🛡️ Executive Security Audit Brief", md)
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn(sample["domain"], md)
        self.assertIn(sample["domain"], html)

if __name__ == "__main__":
    unittest.main()
