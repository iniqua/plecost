from __future__ import annotations
import asyncio
from typing import Optional
import typer
from rich.console import Console
from plecost.models import ScanOptions

app = typer.Typer(name="plecost", help="The best black-box WordPress security scanner.")
console = Console()

_ALL_MODULE_NAMES = [
    "fingerprint", "waf", "plugins", "themes", "users", "xmlrpc",
    "rest_api", "misconfigs", "directory_listing", "http_headers",
    "ssl_tls", "debug_exposure", "content_analysis", "auth", "cves",
]


@app.command()
def scan(
    url: str = typer.Argument(..., help="Target WordPress URL"),
    user: Optional[str] = typer.Option(None, "--user", "-u", help="WordPress username"),
    password: Optional[str] = typer.Option(None, "--password", "-p", help="WordPress password"),
    proxy: Optional[str] = typer.Option(None, help="Proxy URL (http://host:port or socks5://host:port)"),
    concurrency: int = typer.Option(10, help="Number of concurrent requests"),
    timeout: int = typer.Option(10, help="Request timeout in seconds"),
    modules: Optional[str] = typer.Option(None, help="Comma-separated list of modules to run"),
    skip_modules: Optional[str] = typer.Option(None, help="Comma-separated list of modules to skip"),
    stealth: bool = typer.Option(False, help="Stealth mode: random UA, slower"),
    aggressive: bool = typer.Option(False, help="Aggressive mode: max concurrency"),
    output: Optional[str] = typer.Option(None, "-o", "--output", help="Save JSON report to file"),
    random_user_agent: bool = typer.Option(False, "--random-user-agent", "--rua"),
    verify_ssl: bool = typer.Option(True, help="Verify SSL certificates"),
    force: bool = typer.Option(False, help="Continue even if WordPress not detected"),
    quiet: bool = typer.Option(False, help="Only show HIGH and CRITICAL findings"),
) -> None:
    """Scan a WordPress site for security vulnerabilities."""
    opts = ScanOptions(
        url=url,
        concurrency=50 if aggressive else concurrency,
        timeout=timeout,
        proxy=proxy,
        modules=modules.split(",") if modules else None,
        skip_modules=skip_modules.split(",") if skip_modules else [],
        credentials=(user, password) if user and password else None,
        stealth=stealth,
        aggressive=aggressive,
        random_user_agent=random_user_agent,
        verify_ssl=verify_ssl,
        force=force,
        output=output,
    )

    try:
        uvloop = __import__("uvloop")
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    except ImportError:
        pass

    from plecost.scanner import Scanner
    from plecost.reporters.terminal import TerminalReporter
    from plecost.reporters.json_reporter import JSONReporter

    result = asyncio.run(Scanner(opts).run())

    TerminalReporter(result, console=console, quiet=quiet).print()

    if output:
        JSONReporter(result).save(output)
        console.print(f"\n[green]Report saved to {output}[/green]")

    # Exit code based on findings
    if any(f.severity.value in ("CRITICAL", "HIGH") for f in result.findings):
        raise typer.Exit(code=1)


@app.command("update-db")
def update_db(
    db_path: Optional[str] = typer.Option(None, help="Path to save the database"),
) -> None:
    """Download and update the CVE database."""
    from pathlib import Path
    if not db_path:
        db_path = str(Path.home() / ".plecost" / "db" / "plecost.db")

    console.print(f"[cyan]Updating CVE database at {db_path}...[/cyan]")
    from plecost.database.updater import DatabaseUpdater

    try:
        uvloop = __import__("uvloop")
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    except ImportError:
        pass

    asyncio.run(DatabaseUpdater(db_path=db_path).run())
    console.print("[green]Database updated successfully.[/green]")


modules_app = typer.Typer(help="Manage scanner modules.")
app.add_typer(modules_app, name="modules")


@modules_app.command("list")
def modules_list() -> None:
    """List all available scanner modules."""
    from rich.table import Table
    table = Table(title="Available Modules")
    table.add_column("Module", style="cyan")
    table.add_column("Depends On")
    table.add_column("Description")
    descriptions = {
        "fingerprint": "Detect WordPress version (9 methods)",
        "waf": "Detect WAF/CDN (Cloudflare, Sucuri, etc.)",
        "plugins": "Enumerate plugins (passive + brute-force)",
        "themes": "Enumerate themes (passive + brute-force)",
        "users": "Enumerate users (REST API, author archives)",
        "xmlrpc": "Check XML-RPC security (pingback, multicall)",
        "rest_api": "Check REST API exposure and misconfigs",
        "misconfigs": "Check for exposed sensitive files",
        "directory_listing": "Check for open directory listing",
        "http_headers": "Check for missing security headers",
        "ssl_tls": "Check SSL/TLS configuration",
        "debug_exposure": "Detect debug mode and PHP exposure",
        "content_analysis": "Detect card skimming and hardcoded secrets",
        "auth": "Authenticated scan (requires --user --password)",
        "cves": "Correlate found software with CVE database",
    }
    deps = {
        "fingerprint": "—", "waf": "—",
        "plugins": "fingerprint", "themes": "fingerprint",
        "users": "fingerprint", "xmlrpc": "fingerprint",
        "rest_api": "fingerprint", "misconfigs": "fingerprint",
        "directory_listing": "fingerprint", "http_headers": "fingerprint",
        "ssl_tls": "fingerprint", "debug_exposure": "fingerprint",
        "content_analysis": "fingerprint", "auth": "fingerprint",
        "cves": "plugins, themes",
    }
    for name in _ALL_MODULE_NAMES:
        table.add_row(name, deps.get(name, "—"), descriptions.get(name, ""))
    console.print(table)


@app.command("explain")
def explain(finding_id: str = typer.Argument(..., help="Finding ID (e.g. PC-XMLRPC-002)")) -> None:
    """Show detailed information about a finding ID."""
    console.print(f"[yellow]Finding ID:[/yellow] {finding_id}")
    console.print("[dim]Tip: Run a scan to see this finding in context.[/dim]")


if __name__ == "__main__":
    app()
