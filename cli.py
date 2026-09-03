"""
Command-Line Interface (CLI) for Spear-Phising & Social Engineering Profiler.
Utilizes Rich for cybersecurity terminal displays and interactive audits.
"""

import argparse
import sys
import io

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

from core.osint_collector import OSINTCollector
from core.org_mapper import OrgMapper
from core.risk_scorer import RiskScorer
from core.ai_profiler import AIProfiler
from core.defense_advisor import DefenseAdvisor
from reports.report_generator import ReportGenerator

console = Console()

def print_banner():
    banner_text = """[bold red]
 ╔══════════════════════════════════════════════════════════════════════════╗
 ║  🛡️  SPEAR-PHISHING & SOCIAL ENGINEERING PROFILER                       ║
 ║      AI-Assisted Human Attack Surface & Defense Auditor                  ║
 ╚══════════════════════════════════════════════════════════════════════════╝[/bold red]
 [dim cyan]Defensive Security Standard | MITRE ATT&CK Mapping | NIST CSF Aligned[/dim cyan]
"""
    console.print(banner_text)

def run_audit(domain: str, sample_key: str = None, save_report: bool = True):
    print_banner()

    collector = OSINTCollector()
    mapper = OrgMapper()
    scorer = RiskScorer()
    profiler = AIProfiler()
    advisor = DefenseAdvisor()
    reporter = ReportGenerator()

    # Determine Organization Data
    sample_data = None
    if sample_key:
        sample_data = mapper.get_sample_profile(sample_key)
        if not sample_data:
            console.print(f"[bold red]Error:[/] Sample profile '{sample_key}' not found.")
            sys.exit(1)
        domain = sample_data.get("domain", domain)
        org_name = sample_data.get("name", "Target Organization")
        industry = sample_data.get("industry", "Enterprise")
        departments_data = sample_data.get("departments", [])
    else:
        org_name = domain.split(".")[0].capitalize() + " Corp"
        industry = "Technology & Business Services"
        departments_data = mapper.generate_default_departments()

    with Progress(
        SpinnerColumn("dots", style="bold cyan"),
        TextColumn("[bold cyan]{task.description}"),
        console=console,
        transient=True
    ) as progress:
        # Phase 1: OSINT Recon
        task1 = progress.add_task(f"Executing OSINT & DNS Telemetry Scan on [bold white]{domain}[/]...", total=None)
        domain_recon = collector.inspect_domain(domain)
        
        # If sample data has mock DNS posture, blend it for realistic simulation if DNS lookup was empty
        if sample_data and sample_data.get("dns_posture") and domain_recon["dmarc"]["status"] == "missing":
            mock_dns = sample_data["dns_posture"]
            if mock_dns.get("dmarc_policy"):
                domain_recon["dmarc"]["policy"] = mock_dns["dmarc_policy"]
                domain_recon["dmarc"]["status"] = "configured"
            if mock_dns.get("spf_qualifier"):
                domain_recon["spf"]["qualifier"] = mock_dns["spf_qualifier"]
                domain_recon["spf"]["status"] = "configured"
            domain_recon["spoof_assessment"] = collector._assess_spoofability(domain_recon["dmarc"], domain_recon["spf"])
            if sample_data.get("tech_stack"):
                from config import TECH_STACK_SIGNATURES
                for ts in sample_data["tech_stack"]:
                    if not any(d["name"] == ts for d in domain_recon["tech_stack"]):
                        domain_recon["tech_stack"].append({
                            "name": ts,
                            "indicator_found": "Profile Catalog Signature",
                            "threat_vector": TECH_STACK_SIGNATURES.get(ts, {}).get("threat_vector", "Credential Lures"),
                            "risk_multiplier": TECH_STACK_SIGNATURES.get(ts, {}).get("risk_multiplier", 1.2)
                        })

        progress.update(task1, completed=True)

        # Phase 2: Org Surface Mapping
        task2 = progress.add_task("Modeling Human Attack Surface & Department Privileges...", total=None)
        org_model = mapper.build_custom_organization(org_name, domain, industry, departments_data)
        progress.update(task2, completed=True)

        # Phase 3: Risk Scoring (SERI)
        task3 = progress.add_task("Computing Social Engineering Risk Index (SERI)...", total=None)
        seri_results = scorer.calculate_seri(domain_recon, org_model)
        progress.update(task3, completed=True)

        # Phase 4: AI Susceptibility Profiling
        task4 = progress.add_task("Synthesizing Department Pretexting Vectors & Cognitive Triggers...", total=None)
        ai_profile = profiler.profile_organization(domain_recon, org_model, seri_results)
        progress.update(task4, completed=True)

        # Phase 5: Defense Advisor & Countermeasures
        task5 = progress.add_task("Formulating CISO Technical Controls & Awareness Playbooks...", total=None)
        defense_plan = advisor.generate_remediation_roadmap(domain_recon, org_model, seri_results)
        progress.update(task5, completed=True)

    # 1. Display Header & SERI Scorecard
    score = seri_results["seri_score"]
    tier = seri_results["risk_tier"]
    color = "red" if score > 80 else "yellow" if score > 50 else "green"

    seri_panel = Panel(
        f"[bold white]Target Domain:[/] [cyan]{domain}[/] | [bold white]Organization:[/] [cyan]{org_name}[/]\n"
        f"[bold white]Social Engineering Risk Index (SERI):[/] [{color} bold text-xl]{score} / 100[/{color} bold text-xl] [{color} bold]({tier} RISK)[/{color} bold]\n"
        f"[dim]{seri_results['description']}[/dim]\n\n"
        f"• [bold]Domain Spoofability Score:[/] {seri_results['component_scores']['domain_spoof_risk']['score']}/100 (Weight: 35%)\n"
        f"• [bold]Human Attack Surface Score:[/] {seri_results['component_scores']['human_attack_surface_risk']['score']}/100 (Weight: 40%)\n"
        f"• [bold]Tech Stack / SaaS Risk Score:[/] {seri_results['component_scores']['tech_stack_exposure_risk']['score']}/100 (Weight: 25%)",
        title="[bold red]📊 Executive SERI Scorecard[/bold red]",
        border_style=color,
        box=box.ROUNDED
    )
    console.print(seri_panel)

    # 2. Display Technical OSINT Findings
    dns_table = Table(title="🌐 Domain Defense & Email Anti-Spoofing Posture", box=box.SIMPLE_HEAVY)
    dns_table.add_column("Defense Layer", style="bold cyan")
    dns_table.add_column("Status / Policy", style="bold white")
    dns_table.add_column("Technical Assessment", style="white")

    dmarc_pol = domain_recon["dmarc"].get("policy", "missing")
    dmarc_style = "green" if dmarc_pol == "reject" else "yellow" if dmarc_pol == "quarantine" else "red"
    dns_table.add_row("DMARC Enforcement", f"[{dmarc_style}]{dmarc_pol.upper()}[/{dmarc_style}]", domain_recon["dmarc"].get("description", ""))

    spf_qual = domain_recon["spf"].get("qualifier", "missing")
    spf_style = "green" if spf_qual == "hardfail" else "yellow" if spf_qual == "softfail" else "red"
    dns_table.add_row("SPF Qualifier", f"[{spf_style}]{spf_qual.upper()}[/{spf_style}]", domain_recon["spf"].get("description", ""))

    spoof_stat = domain_recon["spoof_assessment"]["threat_level"]
    spoof_style = "red" if spoof_stat in ["HIGH", "CRITICAL"] else "green"
    dns_table.add_row("Spoofability Rating", f"[{spoof_style}]{spoof_stat}[/{spoof_style}]", domain_recon["spoof_assessment"]["summary"])

    console.print(dns_table)

    # 3. Department Vulnerability Rankings
    dept_table = Table(title="🏢 Department Human Attack Surface & Vulnerability", box=box.SIMPLE_HEAVY)
    dept_table.add_column("Department", style="bold cyan")
    dept_table.add_column("Headcount", justify="center")
    dept_table.add_column("Privilege", style="magenta")
    dept_table.add_column("Risk Score", justify="center", style="bold")
    dept_table.add_column("Human Firewall Status", style="bold")

    for dept in ai_profile.get("department_profiles", []):
        r_info = dept.get("human_firewall_readiness", {})
        r_rating = r_info.get("rating", "UNKNOWN")
        r_style = "red" if r_rating == "VULNERABLE" else "yellow" if "MODERATE" in r_rating else "green"
        dept_table.add_row(
            dept["department"],
            str(dept["headcount"]),
            dept["criticality"],
            f"{dept['risk_score']}/100",
            f"[{r_style}]{r_rating}[/{r_style}]"
        )
    console.print(dept_table)

    # 4. Top Pretexting Scenarios
    console.print("\n[bold red]🎯 Priority Pretexting Scenarios & Cognitive Vulnerabilities:[/bold red]")
    for dept in ai_profile.get("department_profiles", [])[:3]:
        for sc in dept.get("plausible_scenarios", [])[:1]:
            scenario_panel = Panel(
                f"[bold white]{sc['scenario_title']}[/] ([cyan]{sc.get('mitre_technique', 'T1566')}[/])\n\n"
                f"[yellow]Attacker Pretext:[/] {sc['attacker_pretext']}\n"
                f"[magenta]Psychological Hook:[/] {sc['psychological_hook']}\n"
                f"[red]Cognitive Blindspot:[/] {sc['employee_cognitive_blindspot']}\n"
                f"[green]Defensive Indicator:[/] [bold]{sc['defensive_indicator']}[/bold]",
                title=f"[bold cyan]🏢 {dept['department']}[/bold cyan]",
                border_style="cyan",
                box=box.ROUNDED
            )
            console.print(scenario_panel)

    # 5. Top Remediation Priorities
    remed_panel = Panel(
        "\n".join([f"[bold red]{i+1}.[/bold red] {p}" for i, p in enumerate(defense_plan["executive_priorities"])]),
        title="[bold green]🛡️ Immediate CISO Remediation Priorities[/bold green]",
        border_style="green",
        box=box.ROUNDED
    )
    console.print(remed_panel)

    # Save Reports if requested
    if save_report:
        md_text = reporter.generate_markdown_report(domain_recon, org_model, seri_results, ai_profile, defense_plan)
        html_text = reporter.generate_html_report(domain_recon, org_model, seri_results, ai_profile, defense_plan)
        saved = reporter.save_reports(domain, md_text, html_text)
        console.print(f"\n[bold green]✔ Executive Audit Reports Saved:[/] \n  • [cyan]{saved['md']}[/]\n  • [cyan]{saved['html']}[/]")

def main():
    parser = argparse.ArgumentParser(description="Spear-Phishing & Social Engineering Profiler CLI")
    parser.add_argument("-d", "--domain", type=str, default="example.com", help="Domain to audit")
    parser.add_argument("-p", "--profile", type=str, choices=["ApexFintech", "CloudScaleAI", "BioCareHealth"], help="Load sample target profile")
    parser.add_argument("--no-report", action="store_true", help="Do not save reports to disk")
    args = parser.parse_args()

    run_audit(domain=args.domain, sample_key=args.profile, save_report=not args.no_report)

if __name__ == "__main__":
    main()
