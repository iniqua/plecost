from __future__ import annotations
from rich import box
from rich.console import Console, Group
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from plecost.models import Finding, ScanResult, Severity

_SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "white",
}

_SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}


class TerminalReporter:
    def __init__(self, result: ScanResult, console: Console | None = None, quiet: bool = False) -> None:
        self._result = result
        self._console = console or Console()
        self._quiet = quiet

    def print(self) -> None:
        r = self._result
        # Header panel
        lines = [
            f"[bold cyan]URL:[/bold cyan] {r.url}",
            f"[bold cyan]Scan ID:[/bold cyan] {r.scan_id}",
            f"[bold cyan]Timestamp:[/bold cyan] {r.timestamp.isoformat()}",
            f"[bold cyan]Duration:[/bold cyan] {r.duration_seconds}s",
        ]
        if r.blocked:
            lines.append("[bold red]Status:[/bold red] [bold red]BLOCKED — target returned HTTP 403, scan aborted[/bold red]")
        else:
            lines.append(f"[bold cyan]WordPress:[/bold cyan] {'Yes' if r.is_wordpress else 'No'}")
            if r.wordpress_version:
                lines.append(f"[bold cyan]WP Version:[/bold cyan] {r.wordpress_version}")
            if r.waf_detected:
                lines.append(f"[bold cyan]WAF:[/bold cyan] {r.waf_detected}")

        self._console.print(Panel("\n".join(lines), title="[bold]Plecost v4.0 Scan Report[/bold]"))

        # Summary table
        s = r.summary
        summary_table = Table(title="Summary")
        summary_table.add_column("Severity")
        summary_table.add_column("Count", justify="right")
        for sev, count in [("CRITICAL", s.critical), ("HIGH", s.high), ("MEDIUM", s.medium),
                            ("LOW", s.low), ("INFO", s.info)]:
            color = _SEVERITY_COLORS.get(Severity(sev), "white")
            summary_table.add_row(f"[{color}]{sev}[/{color}]", str(count))
        self._console.print(summary_table)

        if not r.findings:
            self._console.print("[green]No findings.[/green]")
            return

        # Findings table
        findings_table = Table(title="Findings", show_lines=True)
        findings_table.add_column("ID", style="bold")
        findings_table.add_column("Severity", width=10)
        findings_table.add_column("Title")
        findings_table.add_column("Module")

        for finding in sorted(r.findings, key=lambda f: list(Severity).index(f.severity)):
            if self._quiet and finding.severity not in (Severity.CRITICAL, Severity.HIGH):
                continue
            color = _SEVERITY_COLORS.get(finding.severity, "white")
            findings_table.add_row(
                finding.id,
                f"[{color}]{finding.severity.value}[/{color}]",
                finding.title,
                finding.module,
            )

        self._console.print(findings_table)

        # Finding details
        for finding in sorted(r.findings, key=lambda f: list(Severity).index(f.severity)):
            if self._quiet and finding.severity not in (Severity.CRITICAL, Severity.HIGH):
                continue
            self._print_finding_detail(finding)

        # Plugins
        if r.plugins:
            plugins_table = Table(title="Detected Plugins")
            plugins_table.add_column("Slug")
            plugins_table.add_column("Version")
            plugins_table.add_column("Known CVEs", justify="right")
            for p in r.plugins:
                if p.vuln_count > 0:
                    cve_cell = f"[bold red]{p.vuln_count}[/bold red]"
                else:
                    cve_cell = "[green]0[/green]"
                plugins_table.add_row(p.slug, p.version or "unknown", cve_cell)
            self._console.print(plugins_table)

            for p in r.plugins:
                if not p.vulns:
                    continue
                cve_table = Table(
                    title=f"[bold]{p.slug}[/bold] — Known Vulnerabilities",
                    show_lines=True,
                )
                cve_table.add_column("CVE ID", style="bold", no_wrap=True)
                cve_table.add_column("Severity", width=10)
                cve_table.add_column("CVSS", justify="right", width=5)
                cve_table.add_column("Exploit", width=7, justify="center")
                cve_table.add_column("Affects versions", no_wrap=True)
                cve_table.add_column("Title")

                sorted_vulns = sorted(
                    p.vulns,
                    key=lambda v: _SEVERITY_ORDER.get(v.severity, 99),
                )
                for v in sorted_vulns:
                    try:
                        sev_enum = Severity(v.severity)
                    except ValueError:
                        sev_enum = Severity.INFO
                    color = _SEVERITY_COLORS.get(sev_enum, "white")
                    cvss = f"{v.cvss_score:.1f}" if v.cvss_score else "N/A"
                    exploit = "[bold red]YES[/bold red]" if v.has_exploit else "no"
                    cve_table.add_row(
                        v.cve_id,
                        f"[{color}]{v.severity}[/{color}]",
                        cvss,
                        exploit,
                        v.version_range,
                        v.title,
                    )
                self._console.print(cve_table)

        # Themes
        if r.themes:
            themes_table = Table(title="Detected Themes")
            themes_table.add_column("Slug")
            themes_table.add_column("Version")
            for t in r.themes:
                themes_table.add_row(
                    t.slug,
                    t.version or "unknown",
                )
            self._console.print(themes_table)

        # Users
        if r.users:
            users_table = Table(title="Detected Users")
            users_table.add_column("Username")
            users_table.add_column("Source")
            for u in r.users:
                users_table.add_row(u.username, u.source)
            self._console.print(users_table)


    def _print_finding_detail(self, finding: Finding) -> None:
        color = _SEVERITY_COLORS.get(finding.severity, "white")
        detail = Table(show_lines=True, box=box.SIMPLE_HEAD, expand=True)
        detail.add_column("Field", style="bold", no_wrap=True, width=14)
        detail.add_column("Value")

        detail.add_row("Description", finding.description)

        first = True
        for key, val in finding.evidence.items():
            label = "Evidence" if first else ""
            detail.add_row(label, f"[bold]{key}:[/bold] {val}")
            first = False

        detail.add_row("Remediation", finding.remediation)

        if finding.references:
            for i, ref in enumerate(finding.references):
                detail.add_row("References" if i == 0 else "", ref)

        if finding.cvss_score is not None:
            detail.add_row("CVSS Score", str(finding.cvss_score))

        title = f"[{color}]{finding.id}[/{color}]  [{color}]{finding.severity.value}[/{color}]  {finding.title}"
        self._console.print(Panel(detail, title=title, title_align="left"))


class VerboseDisplay:
    """Rich Live display for verbose scan progress: modules + real-time findings."""

    _STATUS_ICON = {"pending": " ", "running": "[cyan]⠹[/cyan]", "done": "[green]✓[/green]"}

    def __init__(self, console: Console, module_names: list[str]) -> None:
        self._modules: dict[str, str] = {name: "pending" for name in module_names}
        self._progress: dict[str, tuple[int, int]] = {}  # name -> (current, total)
        self._findings: list[Finding] = []
        self._console = console
        self._live: Live | None = None

    def start(self) -> None:
        self._live = Live(self._render(), console=self._console, refresh_per_second=4)
        self._live.start()

    def stop(self) -> None:
        if self._live:
            self._live.stop()

    def on_module_start(self, name: str) -> None:
        self._modules[name] = "running"
        self._refresh()

    def on_module_done(self, name: str) -> None:
        self._modules[name] = "done"
        self._progress.pop(name, None)
        self._refresh()

    def on_finding(self, finding: Finding) -> None:
        self._findings.append(finding)
        self._refresh()

    def on_module_progress(self, name: str, current: int, total: int) -> None:
        self._progress[name] = (current, total)
        self._refresh()

    def _refresh(self) -> None:
        if self._live:
            self._live.update(self._render())

    def _render(self) -> Group:
        mod_table = Table(title="Módulos", box=box.SIMPLE)
        mod_table.add_column("", width=3)
        mod_table.add_column("Módulo")
        mod_table.add_column("Progreso", width=14)
        for name, state in self._modules.items():
            progress_str = ""
            if state == "running" and name in self._progress:
                cur, tot = self._progress[name]
                pct = int(cur / tot * 100) if tot else 0
                progress_str = f"[cyan]{cur}/{tot}[/cyan] [dim]({pct}%)[/dim]"
            mod_table.add_row(self._STATUS_ICON[state], name, progress_str)

        find_table = Table(title=f"Findings ({len(self._findings)})", box=box.SIMPLE)
        find_table.add_column("Severidad", width=10)
        find_table.add_column("ID")
        find_table.add_column("Título")
        for f in self._findings[-20:]:
            color = _SEVERITY_COLORS.get(f.severity, "white")
            find_table.add_row(f"[{color}]{f.severity.value}[/{color}]", f.id, f.title)

        return Group(mod_table, find_table)
