from __future__ import annotations
import asyncio
from pathlib import Path
from typing import Any, Optional
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
    url: Optional[str] = typer.Argument(None, help="Target WordPress URL"),
    targets: Optional[str] = typer.Option(None, "--targets", "-T", help="File with one URL per line"),
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
    # Resolve list of URLs to scan
    if targets:
        targets_path = Path(targets)
        if not targets_path.exists():
            console.print(f"[red]Targets file not found: {targets}[/red]")
            raise typer.Exit(1)
        raw_lines = targets_path.read_text().splitlines()
        urls = [line.strip() for line in raw_lines if line.strip() and not line.strip().startswith("#")]
        if not urls:
            console.print("[red]Targets file is empty or contains only comments.[/red]")
            raise typer.Exit(1)
    elif url:
        urls = [url]
    else:
        console.print("[red]Error: provide a URL argument or --targets file.[/red]")
        raise typer.Exit(1)

    try:
        uvloop = __import__("uvloop")
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    except ImportError:
        pass

    from plecost.scanner import Scanner
    from plecost.reporters.terminal import TerminalReporter
    from plecost.reporters.json_reporter import JSONReporter

    has_critical = False
    for i, target_url in enumerate(urls):
        if i > 0:
            console.print("\n" + "=" * 80 + "\n")

        opts = ScanOptions(
            url=target_url,
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

        result = asyncio.run(Scanner(opts).run())
        TerminalReporter(result, console=console, quiet=quiet).print()

        if output and len(urls) == 1:
            JSONReporter(result).save(output)
            console.print(f"\n[green]Report saved to {output}[/green]")
        elif output and len(urls) > 1:
            # Save each result with a suffix
            out_path = Path(output)
            target_output = str(out_path.with_stem(f"{out_path.stem}_{i + 1}"))
            JSONReporter(result).save(target_output)
            console.print(f"\n[green]Report saved to {target_output}[/green]")

        if any(f.severity.value in ("CRITICAL", "HIGH") for f in result.findings):
            has_critical = True

    if has_critical:
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


_FINDINGS_REGISTRY: dict[str, dict[str, Any]] = {
    "PC-FP-001": {
        "title": "WordPress version disclosed via meta generator tag",
        "severity": "LOW",
        "description": "The WordPress version is exposed in the HTML meta generator tag, allowing attackers to target known vulnerabilities for that version.",
        "remediation": "Remove the generator meta tag. Add to functions.php: remove_action('wp_head', 'wp_generator');",
        "references": ["https://wordpress.org/support/article/hardening-wordpress/"],
        "remediation_id": "REM-FP-001",
    },
    "PC-FP-002": {
        "title": "WordPress version disclosed via readme.html",
        "severity": "LOW",
        "description": "The /readme.html file is publicly accessible and discloses the WordPress version.",
        "remediation": "Delete /readme.html from the server root.",
        "references": ["https://wordpress.org/support/article/hardening-wordpress/"],
        "remediation_id": "REM-FP-002",
    },
    "PC-USR-001": {
        "title": "User enumeration via REST API",
        "severity": "MEDIUM",
        "description": "The WordPress REST API endpoint /wp-json/wp/v2/users exposes a list of usernames without authentication.",
        "remediation": "Restrict the REST API users endpoint. Add to functions.php: add_filter('rest_endpoints', function($e){ unset($e['/wp/v2/users']); return $e; });",
        "references": ["https://www.wordfence.com/learn/wordpress-rest-api/"],
        "remediation_id": "REM-USR-001",
    },
    "PC-USR-002": {
        "title": "User enumeration via author archives",
        "severity": "MEDIUM",
        "description": "WordPress author archive URLs (/?author=N) redirect to /author/username/, exposing valid usernames.",
        "remediation": "Redirect /?author=N to homepage. Add rewrite rules or use a security plugin.",
        "references": [],
        "remediation_id": "REM-USR-002",
    },
    "PC-XMLRPC-001": {
        "title": "XML-RPC endpoint is accessible",
        "severity": "MEDIUM",
        "description": "The xmlrpc.php endpoint is publicly accessible. It can be abused for brute force attacks and DoS amplification.",
        "remediation": "Disable XML-RPC if not needed. Add to .htaccess: <Files xmlrpc.php>\\nOrder Deny,Allow\\nDeny from all\\n</Files>",
        "references": ["https://www.wordfence.com/learn/xml-rpc/"],
        "remediation_id": "REM-XMLRPC-001",
    },
    "PC-XMLRPC-002": {
        "title": "XML-RPC pingback.ping enabled (DoS amplification)",
        "severity": "HIGH",
        "description": "The pingback.ping method is enabled in XML-RPC, allowing attackers to use your site as a DoS amplification vector against third parties.",
        "remediation": "Disable pingbacks: add_filter('xmlrpc_methods', function($m){ unset($m['pingback.ping']); return $m; });",
        "references": ["https://blog.sucuri.net/2014/03/more-than-162000-wordpress-sites-used-for-distributed-denial-of-service-attack.html"],
        "remediation_id": "REM-XMLRPC-002",
    },
    "PC-XMLRPC-003": {
        "title": "XML-RPC system.listMethods exposed",
        "severity": "LOW",
        "description": "system.listMethods is available, allowing attackers to enumerate all available XML-RPC methods.",
        "remediation": "Disable XML-RPC entirely if not needed.",
        "references": [],
        "remediation_id": "REM-XMLRPC-003",
    },
    "PC-REST-001": {
        "title": "REST API link exposed in HTML head",
        "severity": "INFO",
        "description": "The WordPress REST API discovery link is present in the HTML head, confirming WordPress installation.",
        "remediation": "Remove REST API link: remove_action('wp_head', 'rest_output_link_wp_head');",
        "references": [],
        "remediation_id": "REM-REST-001",
    },
    "PC-REST-002": {
        "title": "REST API oEmbed exposes user information",
        "severity": "MEDIUM",
        "description": "The oEmbed endpoint leaks author information.",
        "remediation": "Disable oEmbed or restrict the endpoint.",
        "references": [],
        "remediation_id": "REM-REST-002",
    },
    "PC-REST-003": {
        "title": "REST API CORS misconfiguration",
        "severity": "MEDIUM",
        "description": "The REST API returns Access-Control-Allow-Origin: * allowing any origin to read API responses.",
        "remediation": "Restrict CORS headers in your web server configuration.",
        "references": [],
        "remediation_id": "REM-REST-003",
    },
    "PC-MCFG-001": {"title": "wp-config.php is publicly accessible", "severity": "CRITICAL", "description": "wp-config.php is accessible and exposes database credentials and security keys.", "remediation": "Move wp-config.php one directory above webroot or restrict with .htaccess.", "references": ["https://wordpress.org/support/article/hardening-wordpress/"], "remediation_id": "REM-MCFG-001"},
    "PC-MCFG-002": {"title": "wp-config.php backup exposed", "severity": "CRITICAL", "description": "A backup of wp-config.php is publicly accessible.", "remediation": "Delete all backup files of wp-config.php from the server.", "references": [], "remediation_id": "REM-MCFG-002"},
    "PC-MCFG-003": {"title": ".env file exposed", "severity": "CRITICAL", "description": ".env file is accessible and may expose API keys and secrets.", "remediation": "Restrict .env access via web server configuration.", "references": [], "remediation_id": "REM-MCFG-003"},
    "PC-MCFG-004": {"title": ".git directory exposed", "severity": "HIGH", "description": "The .git directory is accessible, potentially exposing source code and credentials.", "remediation": "Deny access to .git in your web server config.", "references": [], "remediation_id": "REM-MCFG-004"},
    "PC-MCFG-005": {"title": "debug.log exposed", "severity": "HIGH", "description": "WordPress debug log is publicly accessible and may contain sensitive paths and data.", "remediation": "Delete debug.log and set WP_DEBUG_LOG to false.", "references": [], "remediation_id": "REM-MCFG-005"},
    "PC-MCFG-006": {"title": "SQL backup file exposed", "severity": "HIGH", "description": "A database backup file is publicly accessible.", "remediation": "Remove backup files from the webroot immediately.", "references": [], "remediation_id": "REM-MCFG-006"},
    "PC-MCFG-007": {"title": "wp-admin/install.php accessible", "severity": "MEDIUM", "description": "WordPress installation script is accessible.", "remediation": "Restrict access to install.php after installation.", "references": [], "remediation_id": "REM-MCFG-007"},
    "PC-MCFG-008": {"title": "wp-admin/upgrade.php accessible", "severity": "MEDIUM", "description": "WordPress upgrade script is accessible.", "remediation": "Restrict access to upgrade.php after updates.", "references": [], "remediation_id": "REM-MCFG-008"},
    "PC-MCFG-009": {"title": "readme.html discloses WP version", "severity": "LOW", "description": "readme.html is accessible and may disclose WordPress version.", "remediation": "Delete /readme.html from the server.", "references": [], "remediation_id": "REM-MCFG-009"},
    "PC-MCFG-010": {"title": "license.txt accessible", "severity": "LOW", "description": "license.txt confirms WordPress installation.", "remediation": "Delete /license.txt from the server.", "references": [], "remediation_id": "REM-MCFG-010"},
    "PC-MCFG-011": {"title": "wlwmanifest.xml exposed", "severity": "LOW", "description": "Exposes Windows Live Writer endpoint.", "remediation": "remove_action('wp_head', 'wlwmanifest_link');", "references": [], "remediation_id": "REM-MCFG-011"},
    "PC-MCFG-012": {"title": "wp-cron.php externally accessible", "severity": "MEDIUM", "description": "wp-cron.php can be triggered by anyone.", "remediation": "define('DISABLE_WP_CRON', true); and use real server cron.", "references": [], "remediation_id": "REM-MCFG-012"},
    "PC-DIR-001": {"title": "Directory listing in /wp-content/", "severity": "HIGH", "description": "Directory listing is enabled in /wp-content/.", "remediation": "Add 'Options -Indexes' to .htaccess.", "references": [], "remediation_id": "REM-DIR-001"},
    "PC-DIR-002": {"title": "Directory listing in /wp-content/plugins/", "severity": "HIGH", "description": "Plugin directory listing enabled.", "remediation": "Add 'Options -Indexes' to .htaccess.", "references": [], "remediation_id": "REM-DIR-002"},
    "PC-DIR-003": {"title": "Directory listing in /wp-content/themes/", "severity": "HIGH", "description": "Theme directory listing enabled.", "remediation": "Add 'Options -Indexes' to .htaccess.", "references": [], "remediation_id": "REM-DIR-003"},
    "PC-DIR-004": {"title": "Directory listing in /wp-content/uploads/", "severity": "HIGH", "description": "Uploads directory listing enabled.", "remediation": "Add 'Options -Indexes' to .htaccess.", "references": [], "remediation_id": "REM-DIR-004"},
    "PC-HDR-001": {"title": "Missing HSTS header", "severity": "MEDIUM", "description": "Strict-Transport-Security header is absent.", "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload", "references": ["https://owasp.org/www-project-secure-headers/"], "remediation_id": "REM-HDR-001"},
    "PC-HDR-002": {"title": "Missing X-Frame-Options", "severity": "MEDIUM", "description": "X-Frame-Options header is absent, allowing clickjacking.", "remediation": "Add: X-Frame-Options: SAMEORIGIN", "references": [], "remediation_id": "REM-HDR-002"},
    "PC-HDR-003": {"title": "Missing X-Content-Type-Options", "severity": "LOW", "description": "X-Content-Type-Options header is absent.", "remediation": "Add: X-Content-Type-Options: nosniff", "references": [], "remediation_id": "REM-HDR-003"},
    "PC-HDR-004": {"title": "Missing Content-Security-Policy", "severity": "MEDIUM", "description": "CSP header is absent.", "remediation": "Implement a Content-Security-Policy header.", "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"], "remediation_id": "REM-HDR-004"},
    "PC-HDR-005": {"title": "Missing Referrer-Policy", "severity": "LOW", "description": "Referrer-Policy header is absent.", "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin", "references": [], "remediation_id": "REM-HDR-005"},
    "PC-HDR-006": {"title": "Missing Permissions-Policy", "severity": "LOW", "description": "Permissions-Policy header is absent.", "remediation": "Add a Permissions-Policy header restricting unused browser features.", "references": [], "remediation_id": "REM-HDR-006"},
    "PC-HDR-007": {"title": "Server header discloses version", "severity": "LOW", "description": "The Server header reveals web server software and version.", "remediation": "Configure web server to suppress version info.", "references": [], "remediation_id": "REM-HDR-007"},
    "PC-HDR-008": {"title": "X-Powered-By discloses PHP version", "severity": "LOW", "description": "PHP version is exposed via X-Powered-By header.", "remediation": "Set expose_php = Off in php.ini", "references": [], "remediation_id": "REM-HDR-008"},
    "PC-SSL-001": {"title": "HTTP to HTTPS redirect missing", "severity": "HIGH", "description": "The site does not redirect HTTP to HTTPS.", "remediation": "Configure 301 redirect from HTTP to HTTPS in web server config.", "references": [], "remediation_id": "REM-SSL-001"},
    "PC-SSL-002": {"title": "Invalid or expired SSL certificate", "severity": "HIGH", "description": "The SSL certificate is invalid or expired.", "remediation": "Renew the SSL certificate immediately.", "references": [], "remediation_id": "REM-SSL-002"},
    "PC-SSL-003": {"title": "HSTS not configured", "severity": "MEDIUM", "description": "HSTS is not configured.", "remediation": "Enable HSTS in web server configuration.", "references": [], "remediation_id": "REM-SSL-003"},
    "PC-DBG-001": {"title": "WP_DEBUG active — PHP errors exposed", "severity": "HIGH", "description": "PHP error messages are visible in responses, indicating WP_DEBUG=true.", "remediation": "Set define('WP_DEBUG', false); in wp-config.php for production.", "references": ["https://wordpress.org/support/article/debugging-in-wordpress/"], "remediation_id": "REM-DBG-001"},
    "PC-DBG-003": {"title": "PHP version exposed via X-Powered-By", "severity": "MEDIUM", "description": "PHP version is disclosed in the X-Powered-By response header.", "remediation": "Set expose_php = Off in php.ini", "references": [], "remediation_id": "REM-DBG-003"},
    "PC-CNT-001": {"title": "Potential card skimming script", "severity": "HIGH", "description": "A script with card skimming patterns was detected.", "remediation": "Investigate and remove the suspicious script immediately. Check for site compromise.", "references": ["https://www.imperva.com/learn/application-security/magecart/"], "remediation_id": "REM-CNT-001"},
    "PC-CNT-002": {"title": "Suspicious external iframe", "severity": "MEDIUM", "description": "An external iframe from an unexpected domain was found.", "remediation": "Review all external iframes. Remove unauthorized ones.", "references": [], "remediation_id": "REM-CNT-002"},
    "PC-CNT-003": {"title": "Hardcoded API key in page source", "severity": "MEDIUM", "description": "An API key pattern was found in public page source.", "remediation": "Move secrets to server-side config. Never expose keys in client-side code.", "references": [], "remediation_id": "REM-CNT-003"},
    "PC-WAF-001": {"title": "WAF/CDN detected", "severity": "INFO", "description": "A WAF or CDN was detected. Some findings may be incomplete.", "remediation": "No action needed. WAF is a positive security control.", "references": [], "remediation_id": "REM-WAF-001"},
    "PC-AUTH-001": {"title": "Successful authentication", "severity": "INFO", "description": "Successfully authenticated with provided credentials.", "remediation": "Change default credentials. Use a strong unique password.", "references": [], "remediation_id": "REM-AUTH-001"},
    "PC-AUTH-002": {"title": "Open user registration enabled", "severity": "MEDIUM", "description": "Anyone can register an account.", "remediation": "Disable in Settings > General > Membership.", "references": [], "remediation_id": "REM-AUTH-002"},
}


@app.command("explain")
def explain(finding_id: str = typer.Argument(..., help="Finding ID (e.g. PC-XMLRPC-002)")) -> None:
    """Show detailed information and remediation for a finding ID."""
    from rich.panel import Panel
    fid = finding_id.upper()
    if fid not in _FINDINGS_REGISTRY:
        console.print(f"[red]Unknown finding ID: {fid}[/red]")
        console.print("[dim]Run 'plecost modules list' to see available modules.[/dim]")
        raise typer.Exit(1)
    info = _FINDINGS_REGISTRY[fid]
    sev_colors = {"CRITICAL": "red", "HIGH": "orange3", "MEDIUM": "yellow", "LOW": "cyan", "INFO": "white"}
    color = sev_colors.get(info["severity"], "white")
    console.print(Panel(
        f"[bold]{info['title']}[/bold]\n\n"
        f"[dim]Severity:[/dim] [{color}]{info['severity']}[/{color}]\n"
        f"[dim]Remediation ID:[/dim] {info['remediation_id']}\n\n"
        f"[bold]Description:[/bold]\n{info['description']}\n\n"
        f"[bold]Remediation:[/bold]\n[green]{info['remediation']}[/green]" +
        ("\n\n[bold]References:[/bold]\n" + "\n".join(f"- {r}" for r in info['references']) if info['references'] else ""),
        title=f"[bold]{fid}[/bold]",
        border_style=color,
    ))


if __name__ == "__main__":
    app()
