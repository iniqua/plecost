from __future__ import annotations
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from plecost.models import ScanResult, Severity

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
            for p in r.plugins:
                plugins_table.add_row(p.slug, p.version or "unknown")
            self._console.print(plugins_table)

        # Users
        if r.users:
            users_table = Table(title="Detected Users")
            users_table.add_column("Username")
            users_table.add_column("Source")
            for u in r.users:
                users_table.add_row(u.username, u.source)
            self._console.print(users_table)
