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
            f"[bold cyan]WordPress:[/bold cyan] {'Yes' if r.is_wordpress else 'No'}",
        ]
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

        # Themes
        if r.themes:
            themes_table = Table(title="Detected Themes")
            themes_table.add_column("Slug")
            themes_table.add_column("Version")
            themes_table.add_column("Latest Version")
            themes_table.add_column("Outdated")
            for t in r.themes:
                outdated_marker = "[yellow]Yes[/yellow]" if t.outdated else "No"
                themes_table.add_row(
                    t.slug,
                    t.version or "unknown",
                    t.latest_version or "unknown",
                    outdated_marker,
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


class VerboseDisplay:
    """Rich Live display for verbose scan progress: modules + real-time findings."""

    _STATUS_ICON = {"pending": " ", "running": "[cyan]⠹[/cyan]", "done": "[green]✓[/green]"}

    def __init__(self, console: Console, module_names: list[str]) -> None:
        self._modules: dict[str, str] = {name: "pending" for name in module_names}
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
        self._refresh()

    def on_finding(self, finding: Finding) -> None:
        self._findings.append(finding)
        self._refresh()

    def _refresh(self) -> None:
        if self._live:
            self._live.update(self._render())

    def _render(self) -> Group:
        mod_table = Table(title="Módulos", box=box.SIMPLE)
        mod_table.add_column("", width=3)
        mod_table.add_column("Módulo")
        for name, state in self._modules.items():
            mod_table.add_row(self._STATUS_ICON[state], name)

        find_table = Table(title=f"Findings ({len(self._findings)})", box=box.SIMPLE)
        find_table.add_column("Severidad", width=10)
        find_table.add_column("ID")
        find_table.add_column("Título")
        for f in self._findings[-20:]:
            color = _SEVERITY_COLORS.get(f.severity, "white")
            find_table.add_row(f"[{color}]{f.severity.value}[/{color}]", f.id, f.title)

        return Group(mod_table, find_table)
