from __future__ import annotations
from rich import box
from rich.console import Console, Group
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from plecost.models import Finding, ScanResult, Severity
from plecost.i18n import t

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
            f"[bold cyan]{t('reporter.panel.url')}:[/bold cyan] {r.url}",
            f"[bold cyan]{t('reporter.panel.scan_id')}:[/bold cyan] {r.scan_id}",
            f"[bold cyan]{t('reporter.panel.timestamp')}:[/bold cyan] {r.timestamp.isoformat()}",
            f"[bold cyan]{t('reporter.panel.duration')}:[/bold cyan] {r.duration_seconds}s",
        ]
        if r.blocked:
            lines.append(f"[bold red]{t('reporter.panel.status')}:[/bold red] [bold red]{t('reporter.panel.blocked')}[/bold red]")
        else:
            lines.append(f"[bold cyan]{t('reporter.panel.wordpress')}:[/bold cyan] {t('reporter.panel.yes') if r.is_wordpress else t('reporter.panel.no')}")
            if r.wordpress_version:
                lines.append(f"[bold cyan]{t('reporter.panel.wp_version')}:[/bold cyan] {r.wordpress_version}")
            if r.waf_detected:
                lines.append(f"[bold cyan]{t('reporter.panel.waf')}:[/bold cyan] {r.waf_detected}")

        self._console.print(Panel("\n".join(lines), title=f"[bold]{t('reporter.panel.title')}[/bold]"))

        # Summary table
        s = r.summary
        summary_table = Table(title=t("reporter.table.summary"))
        summary_table.add_column(t("reporter.column.severity"))
        summary_table.add_column(t("reporter.column.count"), justify="right")
        for sev, count in [("CRITICAL", s.critical), ("HIGH", s.high), ("MEDIUM", s.medium),
                            ("LOW", s.low), ("INFO", s.info)]:
            color = _SEVERITY_COLORS.get(Severity(sev), "white")
            summary_table.add_row(f"[{color}]{sev}[/{color}]", str(count))
        self._console.print(summary_table)

        if not r.findings:
            self._console.print(f"[green]{t('reporter.panel.no_findings')}[/green]")
            return

        # Findings table
        findings_table = Table(title=t("reporter.table.findings"), show_lines=True)
        findings_table.add_column(t("reporter.column.id"), style="bold")
        findings_table.add_column(t("reporter.column.severity"), width=10)
        findings_table.add_column(t("reporter.column.title"))
        findings_table.add_column(t("reporter.column.module"))

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
            plugins_table = Table(title=t("reporter.table.detected_plugins"))
            plugins_table.add_column(t("reporter.column.slug"))
            plugins_table.add_column(t("reporter.column.version"))
            plugins_table.add_column(t("reporter.column.known_cves"), justify="right")
            for p in r.plugins:
                if p.vuln_count > 0:
                    cve_cell = f"[bold red]{p.vuln_count}[/bold red]"
                else:
                    cve_cell = "[green]0[/green]"
                plugins_table.add_row(p.slug, p.version or t("reporter.panel.unknown"), cve_cell)
            self._console.print(plugins_table)

            for p in r.plugins:
                if not p.vulns:
                    continue
                cve_table = Table(
                    title=f"[bold]{p.slug}[/bold] — {t('reporter.table.known_vulnerabilities')}",
                    show_lines=True,
                )
                cve_table.add_column(t("reporter.column.cve_id"), style="bold", no_wrap=True)
                cve_table.add_column(t("reporter.column.severity"), width=10)
                cve_table.add_column(t("reporter.column.cvss"), justify="right", width=5)
                cve_table.add_column(t("reporter.column.exploit"), width=7, justify="center")
                cve_table.add_column(t("reporter.column.affects_versions"), no_wrap=True)
                cve_table.add_column(t("reporter.column.title"))

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
            themes_table = Table(title=t("reporter.table.detected_themes"))
            themes_table.add_column(t("reporter.column.slug"))
            themes_table.add_column(t("reporter.column.version"))
            for th in r.themes:
                themes_table.add_row(
                    th.slug,
                    th.version or t("reporter.panel.unknown"),
                )
            self._console.print(themes_table)

        # Users
        if r.users:
            users_table = Table(title=t("reporter.table.detected_users"))
            users_table.add_column(t("reporter.column.username"))
            users_table.add_column(t("reporter.column.source"))
            for u in r.users:
                users_table.add_row(u.username, u.source)
            self._console.print(users_table)


    def _print_finding_detail(self, finding: Finding) -> None:
        color = _SEVERITY_COLORS.get(finding.severity, "white")
        detail = Table(show_lines=True, box=box.SIMPLE_HEAD, expand=True)
        detail.add_column("Field", style="bold", no_wrap=True, width=14)
        detail.add_column("Value")

        detail.add_row(t("reporter.field.description"), finding.description)

        first = True
        for key, val in finding.evidence.items():
            label = t("reporter.field.evidence") if first else ""
            detail.add_row(label, f"[bold]{key}:[/bold] {val}")
            first = False

        detail.add_row(t("reporter.field.remediation"), finding.remediation)

        if finding.references:
            for i, ref in enumerate(finding.references):
                detail.add_row(t("reporter.field.references") if i == 0 else "", ref)

        if finding.cvss_score is not None:
            detail.add_row(t("reporter.field.cvss_score"), str(finding.cvss_score))

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
        mod_table = Table(title=t("verbose.table.modules"), box=box.SIMPLE)
        mod_table.add_column("", width=3)
        mod_table.add_column(t("verbose.column.module"))
        mod_table.add_column(t("verbose.column.progress"), width=14)
        for name, state in self._modules.items():
            progress_str = ""
            if state == "running" and name in self._progress:
                cur, tot = self._progress[name]
                pct = int(cur / tot * 100) if tot else 0
                progress_str = f"[cyan]{cur}/{tot}[/cyan] [dim]({pct}%)[/dim]"
            mod_table.add_row(self._STATUS_ICON[state], name, progress_str)

        find_table = Table(title=t("verbose.table.findings", count=len(self._findings)), box=box.SIMPLE)
        find_table.add_column(t("verbose.column.severity"), width=10)
        find_table.add_column(t("verbose.column.id"))
        find_table.add_column(t("verbose.column.title"))
        for f in self._findings[-20:]:
            color = _SEVERITY_COLORS.get(f.severity, "white")
            find_table.add_row(f"[{color}]{f.severity.value}[/{color}]", f.id, f.title)

        return Group(mod_table, find_table)
