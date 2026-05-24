from __future__ import annotations
import asyncio
from pathlib import Path
from typing import TYPE_CHECKING, Any, List, Optional
import httpx
import typer
from rich.console import Console
from plecost.models import ScanOptions
from plecost.i18n import set_language, t

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession

app = typer.Typer(name="plecost", help="The best black-box WordPress security scanner.")
console = Console()

_ALL_MODULE_NAMES = [
    "fingerprint", "waf", "plugins", "themes", "users", "xmlrpc",
    "rest_api", "misconfigs", "directory_listing", "http_headers",
    "ssl_tls", "debug_exposure", "content_analysis", "auth", "cves",
    "woocommerce",
    "wp_ecommerce",
    "magecart",
    "webshells",
    "brute_force",
    "timthumb",
    "emergency_scripts",
    "wp_hardening",
    "brute",
]


def _parse_module_options(raw: List[str]) -> dict[str, dict[str, str]]:
    """Parse --module-option values like 'woocommerce:mode=semi-active' into a nested dict."""
    result: dict[str, dict[str, str]] = {}
    for item in raw:
        if ":" not in item:
            continue
        module_name, rest = item.split(":", 1)
        if "=" not in rest:
            continue
        key, value = rest.split("=", 1)
        result.setdefault(module_name.strip(), {})[key.strip()] = value.strip()
    return result


@app.command()
def scan(
    url: Optional[str] = typer.Argument(None, help="Target WordPress URL"),
    targets: Optional[str] = typer.Option(None, "--targets", "-T", help="File with one URL per line"),
    user: Optional[str] = typer.Option(None, "--user", "-u", help="WordPress username"),
    password: Optional[str] = typer.Option(None, "--password", "-p", help="WordPress password"),
    proxy: Optional[str] = typer.Option(None, help="Proxy URL (http://host:port or socks5://host:port)"),
    concurrency: int = typer.Option(10, help="Number of concurrent requests"),
    timeout: int = typer.Option(10, help="Request timeout in seconds", envvar="PLECOST_TIMEOUT"),
    modules: Optional[str] = typer.Option(None, help="Comma-separated list of modules to run"),
    skip_modules: Optional[str] = typer.Option(None, help="Comma-separated list of modules to skip"),
    stealth: bool = typer.Option(False, help="Stealth mode: random UA, slower"),
    aggressive: bool = typer.Option(False, help="Aggressive mode: max concurrency"),
    output: Optional[str] = typer.Option(None, "-o", "--output", help="Save JSON report to file", envvar="PLECOST_OUTPUT"),
    random_user_agent: bool = typer.Option(False, "--random-user-agent", "--rua"),
    verify_ssl: bool = typer.Option(True, help="Verify SSL certificates"),
    force: bool = typer.Option(False, help="Continue even if WordPress not detected"),
    deep: bool = typer.Option(False, "--deep", help="Deep mode: scan full plugin/theme wordlist (default: top 150 plugins, top 50 themes)"),
    quiet: bool = typer.Option(False, help="Only show HIGH and CRITICAL findings"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Show real-time module progress and findings during scan"),
    db_url: Optional[str] = typer.Option(None, "--db-url", help="CVE database URL (sqlite+aiosqlite:/// or postgresql+asyncpg://)", envvar="PLECOST_DB_URL"),
    module_option: List[str] = typer.Option(
        [],
        "--module-option",
        help=(
            "Module-specific option: MODULE:KEY=VALUE. Can be repeated. "
            "Example: --module-option woocommerce:mode=semi-active"
        ),
    ),
    lang: Optional[str] = typer.Option(None, "--lang", "-L", help="Language for output (en, es). Overrides PLECOST_LANG env var and system locale.", envvar="PLECOST_LANG"),
    brute_force: bool = typer.Option(False, "--brute-force", help="Enable brute force login attacks (requires discovered usernames)"),
    brute_force_defaults: bool = typer.Option(False, "--brute-force-defaults", help="Use built-in password list for brute force (requires --brute-force)"),
    brute_force_wordlist: Optional[str] = typer.Option(None, "--brute-force-wordlist", help="Path to external password wordlist for brute force"),
    brute_force_combine: bool = typer.Option(False, "--brute-force-combine", help="Combine external wordlist with internal password list"),
) -> None:
    """Scan a WordPress site for security vulnerabilities."""
    if lang:
        set_language(lang)
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
    from plecost.reporters.terminal import TerminalReporter, VerboseDisplay
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
            deep=deep,
            output=output,
            db_url=db_url,
            module_options=_parse_module_options(module_option),
            brute_force=brute_force,
            brute_force_use_defaults=brute_force_defaults,
            brute_force_wordlist=brute_force_wordlist,
            brute_force_combine=brute_force_combine,
        )

        if deep:
            typer.echo(
                "[!] Deep mode: mu-plugins PHP probe active. "
                "This sends POST requests to PHP files on the target server. "
                "Only use with explicit authorization."
            )

        display = None
        if verbose:
            display = VerboseDisplay(console, module_names=_ALL_MODULE_NAMES)
            display.start()

        try:
            result = asyncio.run(Scanner(
                opts,
                on_module_start=display.on_module_start if display else None,
                on_module_done=display.on_module_done if display else None,
                on_finding=display.on_finding if display else None,
                on_module_progress=display.on_module_progress if display else None,
            ).run())
        except KeyboardInterrupt:
            raise typer.Exit(0)
        finally:
            if display:
                display.stop()

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


async def _get_metadata(sf: "async_sessionmaker[AsyncSession]", key: str) -> "str | None":
    from plecost.database.models import DbMetadata

    async with sf() as session:
        row = await session.get(DbMetadata, key)
        return str(row.value) if row else None


async def _set_metadata(sf: "async_sessionmaker[AsyncSession]", key: str, value: str) -> None:
    from plecost.database.models import DbMetadata

    async with sf() as session:
        row = await session.get(DbMetadata, key)
        if row:
            row.value = value
        else:
            session.add(DbMetadata(key=key, value=value))
        await session.commit()


async def _apply_sqlite_migrations(conn: Any) -> None:
    """Add columns introduced after the initial schema release (SQLite ALTER TABLE)."""
    from sqlalchemy import text

    migrations: list[tuple[str, str, str]] = [
        # (table, column, column_definition)
        ("themes_wordlist", "active_installs", "INTEGER DEFAULT 0"),
    ]
    for table, column, definition in migrations:
        result = await conn.execute(text(f"PRAGMA table_info({table})"))
        existing_columns = {row[1] for row in result.fetchall()}
        if column not in existing_columns:
            await conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {definition}"))


async def _sync_active_installs(sf: "async_sessionmaker[AsyncSession]") -> None:
    """
    Populate active_installs for PluginsWordlist and ThemesWordlist by calling the
    WordPress.org public API. Only updates slugs already present in the DB (AC-5).
    If the API is unavailable, logs a warning and returns without crashing (AC-4).
    Uses paginated requests (100 per page, max 50 pages) per AC-2/AC-8.
    """
    from sqlalchemy import select, update
    from plecost.database.models import PluginsWordlist, ThemesWordlist

    _MAX_PAGES = 50
    _PER_PAGE = 100

    async def _fetch_and_update(
        client: httpx.AsyncClient,
        session_factory: "async_sessionmaker[AsyncSession]",
        api_url_template: str,
        items_key: str,
        model: type,
    ) -> None:
        """Paginate through WP.org API and update matching slugs in the DB."""
        # Collect all (slug, active_installs) from the API
        collected: dict[str, int] = {}
        for page in range(1, _MAX_PAGES + 1):
            url = api_url_template.format(page=page, per_page=_PER_PAGE)
            try:
                resp = await client.get(url, timeout=30.0)
                resp.raise_for_status()
                data = resp.json()
            except Exception:
                # Partial failure: stop fetching more pages but keep what we have
                break

            items = data.get(items_key, [])
            if not items:
                break  # No more results

            for item in items:
                slug = item.get("slug", "")
                installs = item.get("active_installs", 0)
                if slug:
                    collected[slug] = int(installs)

            # If we got fewer items than requested, we've reached the last page
            if len(items) < _PER_PAGE:
                break

        if not collected:
            return

        # Update only slugs that exist in the DB (AC-5)
        async with session_factory() as session:
            # Retrieve existing slugs from the DB
            result = await session.execute(select(model.slug))  # type: ignore[attr-defined]
            existing_slugs = {row[0] for row in result.fetchall()}

            updates = {slug: installs for slug, installs in collected.items() if slug in existing_slugs}
            if not updates:
                return

            # Batch update
            for slug, installs in updates.items():
                await session.execute(
                    update(model).where(model.slug == slug).values(active_installs=installs)  # type: ignore[attr-defined]
                )
            await session.commit()

    try:
        async with httpx.AsyncClient() as client:
            # Sync plugins
            plugin_url = (
                "https://api.wordpress.org/plugins/info/1.2/"
                "?action=query_plugins"
                "&request[fields][active_installs]=1"
                "&request[per_page]={per_page}"
                "&request[page]={page}"
            )
            await _fetch_and_update(client, sf, plugin_url, "plugins", PluginsWordlist)

            # Sync themes
            theme_url = (
                "https://api.wordpress.org/themes/info/1.1/"
                "?action=query_themes"
                "&request[fields][active_installs]=1"
                "&request[per_page]={per_page}"
                "&request[page]={page}"
            )
            await _fetch_and_update(client, sf, theme_url, "themes", ThemesWordlist)

    except Exception as exc:
        console.print(f"[yellow]Warning: could not sync active_installs from WP.org: {exc}[/yellow]")


async def _clean_low_confidence_records(sf: "async_sessionmaker[AsyncSession]") -> int:
    """
    Remove normalized_vulns records where match_confidence=0.5 and slug is not
    in any known wordlist. These are fallback records from the old pipeline that
    map CVEs to non-existent WordPress slugs, causing false positives.
    Returns the number of records deleted.
    """
    from sqlalchemy import delete, select
    from plecost.database.models import NormalizedVuln, PluginsWordlist, ThemesWordlist

    async with sf() as session:
        # Subquery: slugs present in either wordlist
        known_slugs_q = (
            select(PluginsWordlist.slug)
            .union(select(ThemesWordlist.slug))
        )
        # Count before delete (rowcount from async delete is not reliably typed)
        count_result = await session.execute(
            select(NormalizedVuln).where(
                NormalizedVuln.match_confidence == 0.5,
                NormalizedVuln.slug.notin_(known_slugs_q),
            )
        )
        to_delete = count_result.scalars().all()
        deleted = len(to_delete)
        await session.execute(
            delete(NormalizedVuln).where(
                NormalizedVuln.match_confidence == 0.5,
                NormalizedVuln.slug.notin_(known_slugs_q),
            )
        )
        await session.commit()
        return deleted


async def _update_db_async(db_path: Path, token: "str | None", force_full: bool) -> None:
    import json
    import tempfile

    from plecost.database.downloader import (
        download_full_json,
        download_patch,
        fetch_index,
        fetch_remote_index_checksum,
    )
    from plecost.database.engine import make_engine, make_session_factory
    from plecost.database.models import Base
    from plecost.database.patch_applier import apply_patch, get_last_patch_date

    db_url = f"sqlite+aiosqlite:///{db_path}"
    engine = make_engine(db_url)

    # Create schema if needed
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # Apply incremental schema migrations for columns added after initial release
        await _apply_sqlite_migrations(conn)
    sf = make_session_factory(engine)

    # AC-11: single try/finally guarantees engine.dispose() on all exit paths,
    # including exceptions raised inside _clean_low_confidence_records.
    try:
        # Clean up legacy low-confidence records from the old normalization pipeline
        deleted = await _clean_low_confidence_records(sf)
        if deleted > 0:
            console.print(f"[dim]Cleaned {deleted} low-confidence records from previous pipeline.[/dim]")

        # Check if we need to update (compare remote checksum with local)
        try:
            remote_checksum = await fetch_remote_index_checksum(token)
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                console.print(
                    "[red]CVE patch database not found on GitHub.[/red]\n"
                    "[dim]The 'db-patches' release may not exist yet. "
                    "Run 'plecost build-db' to create the initial database, "
                    "then publish it to GitHub releases.[/dim]"
                )
            elif e.response.status_code == 401:
                console.print(
                    "[red]GitHub authentication failed (401).[/red]\n"
                    "[dim]Check your --token or GITHUB_TOKEN environment variable.[/dim]"
                )
            elif e.response.status_code >= 500:
                console.print(
                    f"[red]GitHub server error ({e.response.status_code}). Try again later.[/red]"
                )
            else:
                console.print(f"[red]GitHub returned {e.response.status_code}: {e}[/red]")
            return
        except httpx.ConnectError:
            console.print(
                "[red]Cannot connect to GitHub. Check your internet connection.[/red]"
            )
            return
        except Exception as e:
            console.print(f"[yellow]Warning: cannot reach GitHub releases: {e}[/yellow]")
            return

        # Load local stored checksum from db_metadata
        local_checksum = await _get_metadata(sf, "index_checksum")

        if local_checksum == remote_checksum and not force_full:
            console.print("[green]CVE database is already up to date.[/green]")
            return

        # Check if DB has data or is first run
        last_patch = await get_last_patch_date(sf)
        is_first_run = (last_patch is None) or force_full

        if is_first_run:
            # Download full.json
            console.print("[bold]First run: downloading full CVE database (~50 MB)...[/bold]")
            console.print("[dim]Subsequent updates will only download daily patches (<100 KB).[/dim]")
            with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
                tmp_path = Path(tmp.name)
            try:
                await download_full_json(tmp_path, token)
                patch_data = json.loads(tmp_path.read_text(encoding="utf-8"))
                upserted, deleted = await apply_patch(patch_data, sf)
                console.print(
                    f"[green]Full database loaded: {upserted} CVEs upserted, {deleted} removed.[/green]"
                )
            finally:
                if tmp_path.exists():
                    tmp_path.unlink()

        # Download and apply missing daily patches
        index = await fetch_index(token)
        raw_patches = index.get("patches")
        patch_list: list[Any] = list(raw_patches) if isinstance(raw_patches, list) else []
        patches_typed: list[dict[str, Any]] = [p for p in patch_list if isinstance(p, dict)]

        # Find patches newer than last applied
        last_patch_date = await get_last_patch_date(sf) or "0000-00-00"
        missing = [p for p in patches_typed if str(p.get("date", "")) > last_patch_date]

        if missing:
            console.print(f"[bold]Applying {len(missing)} new patch(es)...[/bold]")
            for patch_info in sorted(missing, key=lambda x: x.get("date", "")):
                patch_data = await download_patch(
                    str(patch_info["url"]),
                    str(patch_info["sha256"]),
                    token,
                )
                upserted, deleted = await apply_patch(patch_data, sf)
                console.print(
                    f"  [dim]{patch_info['date']}[/dim]: {upserted} upserted, {deleted} removed"
                )
        else:
            if not is_first_run:
                console.print("[green]No new patches available.[/green]")

        # Apply local corrections for known wrong upstream mappings
        from plecost.database.local_patches import apply_local_corrections
        upserted_c, deleted_c = await apply_local_corrections(sf)
        if upserted_c or deleted_c:
            console.print(
                f"[dim]Local corrections applied: {upserted_c} upserted, {deleted_c} corrected.[/dim]"
            )

        # Save remote checksum locally
        await _set_metadata(sf, "index_checksum", remote_checksum)

        # Populate active_installs from WP.org API (AC-1 to AC-8)
        console.print("[dim]Syncing plugin/theme popularity from WP.org...[/dim]")
        await _sync_active_installs(sf)

        console.print(f"[green]CVE database updated at {db_path}[/green]")
    finally:
        await engine.dispose()


@app.command("update-db")
def update_db(
    db_url: Optional[str] = typer.Option(
        None,
        "--db-url",
        envvar="PLECOST_DB_URL",
        help="Database URL. Default: sqlite at ~/.plecost/db/plecost.db",
    ),
    github_token: Optional[str] = typer.Option(
        None, "--token", envvar="GITHUB_TOKEN",
        help="GitHub token for higher rate limit on downloads",
    ),
    force_full: bool = typer.Option(
        False, "--force-full",
        help="Force download of full.json even if patches are available",
    ),
) -> None:
    """Download and apply CVE database patches from GitHub releases."""
    if not db_url:
        db_path = Path.home() / ".plecost" / "db" / "plecost.db"
        db_path.parent.mkdir(parents=True, exist_ok=True)
    else:
        if db_url.startswith("sqlite"):
            db_path = Path(db_url.replace("sqlite+aiosqlite:///", ""))
            db_path.parent.mkdir(parents=True, exist_ok=True)
        else:
            console.print("[red]update-db only supports SQLite. For PostgreSQL use build-db and load manually.[/red]")
            raise typer.Exit(1)

    try:
        uvloop = __import__("uvloop")
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    except ImportError:
        pass

    asyncio.run(_update_db_async(db_path, github_token, force_full))


modules_app = typer.Typer(help="Manage scanner modules.")
app.add_typer(modules_app, name="modules")


@modules_app.command("list")
def modules_list(
    lang: Optional[str] = typer.Option(None, "--lang", "-L", help="Language for output (en, es).", envvar="PLECOST_LANG"),
) -> None:
    """List all available scanner modules."""
    if lang:
        set_language(lang)
    from rich.table import Table
    table = Table(title=t("cli.modules.table_title"))
    table.add_column(t("cli.modules.column_module"), style="cyan")
    table.add_column(t("cli.modules.column_depends_on"))
    table.add_column(t("cli.modules.column_description"))
    deps = {
        "fingerprint": "—", "waf": "—",
        "plugins": "fingerprint", "themes": "fingerprint",
        "users": "fingerprint", "xmlrpc": "fingerprint",
        "rest_api": "fingerprint", "misconfigs": "fingerprint",
        "directory_listing": "fingerprint", "http_headers": "fingerprint",
        "ssl_tls": "fingerprint", "debug_exposure": "fingerprint",
        "content_analysis": "fingerprint", "auth": "fingerprint",
        "cves": "plugins, themes",
        "woocommerce": "fingerprint",
        "wp_ecommerce": "fingerprint",
        "magecart": "fingerprint, woocommerce, wp_ecommerce",
        "brute_force": "users",
    }
    for name in _ALL_MODULE_NAMES:
        desc = t(f"cli.modules.descriptions.{name}")
        table.add_row(name, deps.get(name, "—"), desc)
    console.print(table)


def _finding_key(finding_id: str) -> str:
    """Convert 'PC-WP-001' → 'pc_wp_001' for i18n key lookup."""
    return finding_id.lower().replace("-", "_")


_FINDINGS_REGISTRY: dict[str, dict[str, Any]] = {
    "PC-WP-001": {
        "title": "WordPress version disclosed via meta generator tag",
        "severity": "LOW",
        "description": "The WordPress version is exposed in the HTML meta generator tag, allowing attackers to target known vulnerabilities for that version.",
        "remediation": "Remove the generator meta tag. Add to functions.php: remove_action('wp_head', 'wp_generator');",
        "references": ["https://wordpress.org/support/article/hardening-wordpress/"],
        "remediation_id": "REM-WP-001",
    },
    "PC-WP-002": {
        "title": "WordPress version disclosed via readme.html",
        "severity": "LOW",
        "description": "The /readme.html file is publicly accessible and discloses the WordPress version.",
        "remediation": "Delete /readme.html from the server root.",
        "references": ["https://wordpress.org/support/article/hardening-wordpress/"],
        "remediation_id": "REM-WP-002",
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
    "PC-XMLRPC-004": {
        "title": "XML-RPC system.multicall enabled (Brute-force amplification)",
        "severity": "HIGH",
        "description": "The system.multicall method is enabled, allowing attackers to bypass rate limits by sending thousands of credentials in a single request.",
        "remediation": "Disable system.multicall: add_filter('xmlrpc_methods', function($m){ unset($m['system.multicall']); return $m; });",
        "references": ["https://kinsta.com/blog/xmlrpc-php/#xmlrpc-brute-force-attacks"],
        "remediation_id": "REM-XMLRPC-004",
    },
    "PC-XMLRPC-005": {
        "title": "XML-RPC Brute-Force Protection Missing",
        "severity": "HIGH",
        "description": "The xmlrpc.php endpoint does not enforce rate limiting on failed authentication attempts.",
        "remediation": "Implement rate limiting via a WAF, security plugin, or Fail2Ban, or disable XML-RPC entirely.",
        "references": ["https://kinsta.com/blog/xmlrpc-php/"],
        "remediation_id": "REM-XMLRPC-005",
    },
    "PC-XMLRPC-006": {
        "title": "XML-RPC Guardrails Active",
        "severity": "INFO",
        "description": "The xmlrpc.php endpoint is accessible, but active defenses (WAF/Rate Limiting) successfully blocked repeated authentication attempts.",
        "remediation": "No immediate action required. Defenses are working as expected.",
        "references": [],
        "remediation_id": "REM-XMLRPC-006",
    },
    # AC-6: publishing methods
    "PC-XMLRPC-007": {
        "title": "XML-RPC publishing methods exposed",
        "severity": "LOW",
        "description": "XML-RPC publishing methods (wp.newPost, metaWeblog.newPost, blogger.newPost) are exposed, allowing content creation via XML-RPC as any authenticated user.",
        "remediation": "Disable publishing methods: add_filter('xmlrpc_methods', function($m){ unset($m['wp.newPost'], $m['metaWeblog.newPost'], $m['blogger.newPost']); return $m; });",
        "references": ["https://kinsta.com/blog/xmlrpc-php/"],
        "remediation_id": "REM-XMLRPC-007",
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
    # AC-1..AC-4: new misconfig findings
    "PC-MCFG-013": {"title": "wp-content/debug.log exposed", "severity": "HIGH", "description": "The WordPress debug log in wp-content is publicly accessible and may contain sensitive server paths and error data.", "remediation": "Delete the file and set WP_DEBUG_LOG to false in wp-config.php. Deny direct access via .htaccess.", "references": ["https://wordpress.org/support/article/debugging-in-wordpress/"], "remediation_id": "REM-MCFG-013"},
    "PC-MCFG-014": {"title": "Adminer database tool exposed", "severity": "CRITICAL", "description": "adminer.php is publicly accessible and provides a full-featured database management interface. Attackers can use it to read, modify, or exfiltrate all data.", "remediation": "Remove adminer.php from the webroot immediately. Never leave database management tools publicly accessible.", "references": ["https://adminer.org/", "https://owasp.org/www-community/vulnerabilities/Insecure_Direct_Object_Reference"], "remediation_id": "REM-MCFG-014"},
    "PC-MCFG-015": {"title": "wp-config.php~ editor backup exposed", "severity": "CRITICAL", "description": "A text editor backup file wp-config.php~ is publicly accessible and exposes database credentials and WordPress secret keys.", "remediation": "Delete wp-config.php~ immediately. Configure your editor to not create backup files in the webroot.", "references": ["https://wordpress.org/support/article/hardening-wordpress/"], "remediation_id": "REM-MCFG-015"},
    "PC-MCFG-016": {"title": "wp-config.php.old backup exposed", "severity": "CRITICAL", "description": "A backup file wp-config.php.old is publicly accessible and exposes database credentials and WordPress secret keys.", "remediation": "Delete wp-config.php.old immediately. Remove all configuration backups from the webroot.", "references": ["https://wordpress.org/support/article/hardening-wordpress/"], "remediation_id": "REM-MCFG-016"},
    "PC-MCFG-017": {"title": "wp-config.php_bak backup exposed", "severity": "CRITICAL", "description": "A backup file wp-config.php_bak is publicly accessible and exposes database credentials and WordPress secret keys.", "remediation": "Delete wp-config.php_bak immediately. Remove all configuration backups from the webroot.", "references": ["https://wordpress.org/support/article/hardening-wordpress/"], "remediation_id": "REM-MCFG-017"},
    "PC-MCFG-018": {"title": "wp-config.php.orig backup exposed", "severity": "CRITICAL", "description": "A backup file wp-config.php.orig is publicly accessible and exposes database credentials and WordPress secret keys.", "remediation": "Delete wp-config.php.orig immediately. Remove all configuration backups from the webroot.", "references": ["https://wordpress.org/support/article/hardening-wordpress/"], "remediation_id": "REM-MCFG-018"},
    "PC-MCFG-019": {"title": "wp-config.php.save backup exposed", "severity": "CRITICAL", "description": "A backup file wp-config.php.save is publicly accessible and exposes database credentials and WordPress secret keys.", "remediation": "Delete wp-config.php.save immediately. Remove all configuration backups from the webroot.", "references": ["https://wordpress.org/support/article/hardening-wordpress/"], "remediation_id": "REM-MCFG-019"},
    "PC-MCFG-020": {"title": "database.sql dump exposed", "severity": "HIGH", "description": "A database dump file database.sql is publicly accessible and may expose the full WordPress database including password hashes, user data, and site content.", "remediation": "Remove database.sql from the webroot immediately. Store backups outside the document root.", "references": ["https://wordpress.org/support/article/hardening-wordpress/"], "remediation_id": "REM-MCFG-020"},
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
    # AC-5: Full Path Disclosure via REST API
    "PC-DBG-002": {"title": "Full Path Disclosure via REST API", "severity": "MEDIUM", "description": "The WordPress REST API leaks the absolute server file-system path in its error response, aiding attackers in mapping the server layout.", "remediation": "Set WP_DEBUG to false in wp-config.php and ensure display_errors = Off in php.ini for production.", "references": ["https://owasp.org/www-community/attacks/Full_Path_Disclosure"], "remediation_id": "REM-DBG-002"},
    "PC-DBG-003": {"title": "PHP version exposed via X-Powered-By", "severity": "MEDIUM", "description": "PHP version is disclosed in the X-Powered-By response header.", "remediation": "Set expose_php = Off in php.ini", "references": [], "remediation_id": "REM-DBG-003"},
    "PC-CNT-001": {"title": "Potential card skimming script", "severity": "HIGH", "description": "A script with card skimming patterns was detected.", "remediation": "Investigate and remove the suspicious script immediately. Check for site compromise.", "references": ["https://www.imperva.com/learn/application-security/magecart/"], "remediation_id": "REM-CNT-001"},
    "PC-CNT-002": {"title": "Suspicious external iframe", "severity": "MEDIUM", "description": "An external iframe from an unexpected domain was found.", "remediation": "Review all external iframes. Remove unauthorized ones.", "references": [], "remediation_id": "REM-CNT-002"},
    "PC-CNT-003": {"title": "Hardcoded API key in page source", "severity": "MEDIUM", "description": "An API key pattern was found in public page source.", "remediation": "Move secrets to server-side config. Never expose keys in client-side code.", "references": [], "remediation_id": "REM-CNT-003"},
    "PC-WAF-001": {"title": "WAF/CDN detected", "severity": "INFO", "description": "A WAF or CDN was detected. Some findings may be incomplete.", "remediation": "No action needed. WAF is a positive security control.", "references": [], "remediation_id": "REM-WAF-001"},
    "PC-AUTH-001": {"title": "Successful authentication", "severity": "INFO", "description": "Successfully authenticated with provided credentials.", "remediation": "Change default credentials. Use a strong unique password.", "references": [], "remediation_id": "REM-AUTH-001"},
    "PC-AUTH-002": {"title": "Open user registration enabled", "severity": "MEDIUM", "description": "Anyone can register an account.", "remediation": "Disable in Settings > General > Membership.", "references": [], "remediation_id": "REM-AUTH-002"},
    "PC-WC-000": {"title": "WooCommerce installation summary", "severity": "INFO", "description": "A summary of the WooCommerce installation was collected.", "remediation": "Review WooCommerce configuration and harden as needed.", "references": ["https://woocommerce.com/document/woocommerce-security/"], "remediation_id": "REM-WC-000"},
    "PC-WC-001": {"title": "WooCommerce detected via Store API", "severity": "INFO", "description": "WooCommerce was detected on this site via the Store API endpoint.", "remediation": "No action required unless WooCommerce is not intentionally installed.", "references": [], "remediation_id": "REM-WC-001"},
    "PC-WC-002": {"title": "WooCommerce version disclosed via readme.txt", "severity": "LOW", "description": "The WooCommerce plugin readme.txt file is publicly accessible and discloses the WooCommerce version.", "remediation": "Delete or restrict access to wp-content/plugins/woocommerce/readme.txt.", "references": [], "remediation_id": "REM-WC-002"},
    "PC-WC-003": {"title": "WooCommerce REST API namespaces exposed", "severity": "LOW", "description": "The WooCommerce REST API namespaces are publicly listed, confirming WooCommerce installation and revealing available API versions.", "remediation": "Restrict the REST API namespace discovery endpoint or require authentication.", "references": [], "remediation_id": "REM-WC-003"},
    "PC-WC-004": {"title": "WooCommerce REST API: customer list exposed without authentication", "severity": "CRITICAL", "description": "The WooCommerce REST API /wc/v3/customers endpoint returns customer data without requiring authentication, exposing PII.", "remediation": "Require authentication for the WooCommerce REST API. Review WooCommerce > Settings > Advanced > REST API.", "references": ["https://woocommerce.com/document/woocommerce-rest-api/"], "remediation_id": "REM-WC-004"},
    "PC-WC-005": {"title": "WooCommerce REST API: order list exposed without authentication", "severity": "CRITICAL", "description": "The WooCommerce REST API /wc/v3/orders endpoint returns order data without requiring authentication.", "remediation": "Require authentication for the WooCommerce REST API.", "references": [], "remediation_id": "REM-WC-005"},
    "PC-WC-006": {"title": "WooCommerce REST API: coupon list exposed without authentication", "severity": "HIGH", "description": "The WooCommerce REST API /wc/v3/coupons endpoint returns coupon codes without requiring authentication.", "remediation": "Require authentication for the WooCommerce REST API.", "references": [], "remediation_id": "REM-WC-006"},
    "PC-WC-007": {"title": "WooCommerce REST API: system status exposed without authentication", "severity": "HIGH", "description": "The WooCommerce REST API /wc/v3/system_status endpoint returns detailed system information without authentication.", "remediation": "Require authentication for the WooCommerce REST API.", "references": [], "remediation_id": "REM-WC-007"},
    "PC-WC-008": {"title": "WooCommerce logs directory listing enabled", "severity": "HIGH", "description": "Directory listing is enabled in /wp-content/uploads/wc-logs/, exposing WooCommerce log files.", "remediation": "Disable directory listing and restrict access to the wc-logs directory.", "references": [], "remediation_id": "REM-WC-008"},
    "PC-WC-009": {"title": "WooCommerce uploads directory accessible", "severity": "HIGH", "description": "The WooCommerce uploads directory is publicly accessible and may expose sensitive files.", "remediation": "Add an .htaccess or nginx rule to restrict direct file access in the uploads directory.", "references": [], "remediation_id": "REM-WC-009"},
    "PC-WC-010": {"title": "WooCommerce Payments plugin detected", "severity": "INFO", "description": "The WooCommerce Payments plugin was detected on this site.", "remediation": "Keep WooCommerce Payments updated to the latest version.", "references": [], "remediation_id": "REM-WC-010"},
    "PC-WC-011": {"title": "WooCommerce Stripe Gateway plugin detected", "severity": "INFO", "description": "The WooCommerce Stripe Gateway plugin was detected on this site.", "remediation": "Keep the Stripe Gateway plugin updated to the latest version.", "references": [], "remediation_id": "REM-WC-011"},
    "PC-WC-012": {"title": "WooCommerce system status retrieved (authenticated)", "severity": "INFO", "description": "WooCommerce system status was successfully retrieved using authenticated API credentials.", "remediation": "No action required. Review system status for any misconfigurations.", "references": [], "remediation_id": "REM-WC-012"},
    "PC-WC-013": {"title": "WooCommerce payment gateway configuration exposed (authenticated)", "severity": "HIGH", "description": "WooCommerce payment gateway configuration was retrieved via authenticated API, potentially exposing API keys and secrets.", "remediation": "Restrict API key permissions and rotate any exposed credentials.", "references": [], "remediation_id": "REM-WC-013"},
    "PC-WC-020": {"title": "CVE-2023-28121: WooCommerce Payments authentication bypass", "severity": "CRITICAL", "description": "CVE-2023-28121 (CVSS 9.8): A critical authentication bypass vulnerability in WooCommerce Payments allows unauthenticated attackers to impersonate any user, including administrators.", "remediation": "Update WooCommerce Payments to version 5.6.2 or later immediately.", "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-28121", "https://woocommerce.com/posts/critical-vulnerability-detected-july-2023/"], "remediation_id": "REM-WC-020"},
    "PC-WC-021": {"title": "CVE-2023-34000: WooCommerce Stripe Gateway IDOR (PII disclosure)", "severity": "HIGH", "description": "CVE-2023-34000 (CVSS 7.5): An Insecure Direct Object Reference (IDOR) vulnerability in the WooCommerce Stripe Gateway plugin allows unauthenticated attackers to access other users' PII.", "remediation": "Update the WooCommerce Stripe Gateway plugin to version 7.4.1 or later.", "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-34000"], "remediation_id": "REM-WC-021"},
    "PC-WPEC-000": {
        "title": "WP eCommerce: resumen de instalación",
        "severity": "INFO",
        "module": "wp_ecommerce",
        "description": "Resumen del análisis del plugin WP eCommerce.",
        "remediation": "Ver findings individuales para detalles de remediación.",
        "remediation_id": "REM-WPEC-000",
        "references": [],
        "cvss_score": None,
    },
    "PC-WPEC-001": {
        "title": "WP eCommerce detectado",
        "severity": "INFO",
        "module": "wp_ecommerce",
        "description": "El plugin WP eCommerce (wp-e-commerce) está instalado y activo.",
        "remediation": "WP eCommerce está abandonado. Considerar migrar a WooCommerce.",
        "remediation_id": "REM-WPEC-001",
        "references": ["https://wordpress.org/plugins/wp-e-commerce/"],
        "cvss_score": None,
    },
    "PC-WPEC-002": {
        "title": "WP eCommerce: versión expuesta via readme.txt",
        "severity": "LOW",
        "module": "wp_ecommerce",
        "description": "La versión de WP eCommerce es accesible públicamente via readme.txt.",
        "remediation": "Bloquear acceso a readme.txt con reglas de servidor web.",
        "remediation_id": "REM-WPEC-002",
        "references": [],
        "cvss_score": 5.3,
    },
    "PC-WPEC-003": {
        "title": "WP eCommerce: plugin abandonado con CVEs sin parchear",
        "severity": "HIGH",
        "module": "wp_ecommerce",
        "description": "WP eCommerce no recibe actualizaciones desde 2020. Todas las instalaciones son vulnerables a CVE-2024-1514 y CVE-2026-1235.",
        "remediation": "Desinstalar WP eCommerce y migrar a WooCommerce u otra alternativa activamente mantenida.",
        "remediation_id": "REM-WPEC-003",
        "references": [
            "https://wordpress.org/plugins/wp-e-commerce/",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-1514",
        ],
        "cvss_score": 8.1,
    },
    "PC-WPEC-004": {
        "title": "WP eCommerce: pasarela ChronoPay detectada",
        "severity": "INFO",
        "module": "wp_ecommerce",
        "description": "El gateway de pago ChronoPay está instalado en WP eCommerce.",
        "remediation": "Verificar que el gateway ChronoPay esté configurado de forma segura.",
        "remediation_id": "REM-WPEC-004",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-1514"],
        "cvss_score": None,
    },
    "PC-WPEC-005": {
        "title": "WP eCommerce: directory listing habilitado en directorio del plugin",
        "severity": "HIGH",
        "module": "wp_ecommerce",
        "description": "El directorio del plugin WP eCommerce tiene directory listing habilitado.",
        "remediation": "Deshabilitar directory listing en el servidor web.",
        "remediation_id": "REM-WPEC-005",
        "references": [],
        "cvss_score": 7.5,
    },
    "PC-WPEC-006": {
        "title": "WP eCommerce: directorio de uploads accesible",
        "severity": "HIGH",
        "module": "wp_ecommerce",
        "description": "El directorio de uploads de WP eCommerce es accesible públicamente.",
        "remediation": "Añadir un archivo .htaccess que niegue acceso directo al directorio wpsc/.",
        "remediation_id": "REM-WPEC-006",
        "references": [],
        "cvss_score": 7.5,
    },
    "PC-WPEC-007": {
        "title": "WP eCommerce: directorio de descargas digitales expuesto",
        "severity": "CRITICAL",
        "module": "wp_ecommerce",
        "description": "El directorio de productos digitales es accesible públicamente, exponiendo archivos de descarga pagados.",
        "remediation": "Configurar el servidor web para negar acceso directo al directorio wpsc/digital/.",
        "remediation_id": "REM-WPEC-007",
        "references": [],
        "cvss_score": 9.1,
    },
    "PC-WPEC-008": {
        "title": "WP eCommerce: script de backup de base de datos accesible",
        "severity": "HIGH",
        "module": "wp_ecommerce",
        "description": "El script db-backup.php del panel admin de WP eCommerce es accesible sin autenticación.",
        "remediation": "Bloquear acceso directo a archivos en wpsc-admin/ con reglas de servidor web.",
        "remediation_id": "REM-WPEC-008",
        "references": [],
        "cvss_score": 7.5,
    },
    "PC-WPEC-009": {
        "title": "WP eCommerce: visor de logs accesible",
        "severity": "MEDIUM",
        "module": "wp_ecommerce",
        "description": "El visor de logs display-log.php de WP eCommerce es accesible sin autenticación.",
        "remediation": "Bloquear acceso directo a archivos en wpsc-admin/ con reglas de servidor web.",
        "remediation_id": "REM-WPEC-009",
        "references": [],
        "cvss_score": 5.3,
    },
    "PC-WPEC-010": {
        "title": "WP eCommerce: endpoint callback de ChronoPay expuesto",
        "severity": "MEDIUM",
        "module": "wp_ecommerce",
        "description": "El endpoint de callback de ChronoPay responde sin verificación de firma.",
        "remediation": "Verificar la configuración de ChronoPay y aplicar validación de firma en callbacks.",
        "remediation_id": "REM-WPEC-010",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-1514"],
        "cvss_score": 5.3,
    },
    "PC-WPEC-020": {
        "title": "CVE-2024-1514: WP eCommerce ChronoPay SQL Injection",
        "severity": "CRITICAL",
        "module": "wp_ecommerce",
        "description": "El endpoint de callback de ChronoPay es vulnerable a SQL Injection (CVE-2024-1514).",
        "remediation": "Desinstalar WP eCommerce. No existe parche disponible.",
        "remediation_id": "REM-WPEC-020",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-1514"],
        "cvss_score": 9.8,
    },
    "PC-WPEC-021": {
        "title": "CVE-2026-1235: WP eCommerce PHP Object Injection",
        "severity": "HIGH",
        "module": "wp_ecommerce",
        "description": "El endpoint AJAX de WP eCommerce es vulnerable a PHP Object Injection (CVE-2026-1235).",
        "remediation": "Desinstalar WP eCommerce. No existe parche disponible.",
        "remediation_id": "REM-WPEC-021",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-1235"],
        "cvss_score": 8.1,
    },
    "PC-MGC-000": {
        "title": "Magecart scan summary",
        "severity": "INFO",
        "description": "The Magecart detection module ran on the eCommerce checkout pages. This finding summarizes what was scanned.",
        "remediation": "No action required. Review other PC-MGC-* findings for actionable issues.",
        "references": ["https://www.riskiq.com/what-is-magecart/"],
        "remediation_id": "REM-MGC-000",
    },
    "PC-MGC-001": {
        "title": "Known Magecart domain script on checkout page",
        "severity": "CRITICAL",
        "description": "A script from a known Magecart card-skimming domain was found loading on a checkout page. This is a strong indicator of a supply-chain compromise targeting payment card data.",
        "remediation": "Immediately remove the malicious script. Audit your theme and plugin files for injected code. Reset all WordPress credentials and rotate payment API keys. Notify your payment processor.",
        "references": [
            "https://www.riskiq.com/what-is-magecart/",
            "https://owasp.org/www-project-top-ten/",
        ],
        "remediation_id": "REM-MGC-001",
    },
    "PC-MGC-002": {
        "title": "Known dropper domain script on checkout page",
        "severity": "CRITICAL",
        "description": "A script from a known dropper domain was found on a checkout page. Dropper scripts typically load secondary payloads, including card skimmers.",
        "remediation": "Immediately remove the malicious script and audit all JavaScript on the checkout flow. Check for secondary payloads or additional injections.",
        "references": ["https://www.riskiq.com/what-is-magecart/"],
        "remediation_id": "REM-MGC-002",
    },
    "PC-MGC-003": {
        "title": "Known exfiltrator domain script on checkout page",
        "severity": "HIGH",
        "description": "A script from a known data exfiltration domain was found on a checkout page. Exfiltrator scripts send captured data (including payment card details) to attacker-controlled servers.",
        "remediation": "Remove the script immediately. Review all external script sources on the checkout page. Implement Content Security Policy (CSP) to restrict script origins.",
        "references": [
            "https://www.riskiq.com/what-is-magecart/",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
        ],
        "remediation_id": "REM-MGC-003",
    },
    "PC-MGC-004": {
        "title": "Known Magecart domain script on non-checkout page",
        "severity": "MEDIUM",
        "description": "A script from a known Magecart-related domain was found on a non-checkout page. While lower risk than checkout exposure, this may indicate site compromise.",
        "remediation": "Investigate the script source. Remove if unauthorized. Check if the domain appears on checkout pages as well.",
        "references": ["https://www.riskiq.com/what-is-magecart/"],
        "remediation_id": "REM-MGC-004",
    },
    "PC-WSH-001": {
        "title": "Known webshell path is accessible",
        "severity": "CRITICAL",
        "description": "A file matching a known webshell filename was found accessible via HTTP.",
        "remediation": "Remove the file immediately. Audit all wp-content directories. Rotate all credentials.",
        "references": [
            "https://media.defense.gov/2020/Jun/09/2002313081/-1/-1/0/CSI-DETECT-AND-PREVENT-WEB-SHELL-MALWARE-20200422.PDF",
            "https://github.com/nsacyber/Mitigating-Web-Shells",
        ],
        "remediation_id": "REM-WSH-001",
    },
    "PC-WSH-100": {
        "title": "PHP file executable in wp-content/uploads",
        "severity": "CRITICAL",
        "description": "A PHP file is accessible and executable inside wp-content/uploads, which should never execute PHP.",
        "remediation": "Remove the file. Add .htaccess to uploads/ to deny PHP execution.",
        "references": [],
        "remediation_id": "REM-WSH-100",
    },
    "PC-WSH-150": {
        "title": "Suspicious PHP file in wp-content/mu-plugins",
        "severity": "CRITICAL",
        "description": "A PHP file matching a known backdoor name was found in must-use plugins directory.",
        "remediation": "Review and remove unexpected files from wp-content/mu-plugins/.",
        "references": [
            "https://blog.sucuri.net/2025/03/hidden-malware-strikes-again-mu-plugins-under-attack.html",
        ],
        "remediation_id": "REM-WSH-150",
    },
    "PC-WSH-200": {
        "title": "Webshell family fingerprint matched in HTTP response",
        "severity": "CRITICAL",
        "description": "The response from a PHP file matches a known webshell family signature.",
        "remediation": "The site is compromised. Take offline, remove webshell, audit all files, rotate all credentials.",
        "references": [
            "https://www.recordedfuture.com/blog/web-shell-analysis-part-1",
        ],
        "remediation_id": "REM-WSH-200",
    },
    "PC-WSH-250": {
        "title": "WordPress core file has been modified",
        "severity": "HIGH",
        "description": "A WordPress core file does not match the official checksum for the installed version.",
        "remediation": "Verify if the modification is authorized. If not, restore the file from a clean WP installation.",
        "references": [
            "https://developer.wordpress.org/reference/functions/get_core_checksums/",
        ],
        "remediation_id": "REM-WSH-250",
    },
    "PC-WSH-300": {
        "title": "Unrecognized plugin detected via WordPress REST API",
        "severity": "HIGH",
        "description": "The WordPress REST API reports an active plugin that was not detected during passive scanning.",
        "remediation": "Verify the plugin is intentionally installed. If unknown, remove it and inspect for malicious code.",
        "references": [
            "https://blog.sucuri.net/2020/01/webshell-in-fake-plugin-blnmrpb-directory.html",
        ],
        "remediation_id": "REM-WSH-300",
    },
    # ------------------------------------------------------------------ #
    # Users module extra findings (AC-3, AC-4, AC-5)                     #
    # ------------------------------------------------------------------ #
    "PC-USR-003": {
        "title": "User enumeration via WordPress sitemap",
        "severity": "INFO",
        "description": "The WordPress user sitemap (/wp-sitemap-users-1.xml) exposes usernames.",
        "remediation": "Disable the user sitemap via add_filter('wp_sitemaps_add_provider', ...).",
        "references": [],
        "remediation_id": "REM-USR-003",
    },
    "PC-USR-004": {
        "title": "User enumeration via RSS feed",
        "severity": "MEDIUM",
        "description": "RSS feed exposes author display names via the dc:creator element.",
        "remediation": "Remove author information from RSS feeds.",
        "references": [],
        "remediation_id": "REM-USR-004",
    },
    "PC-USR-005": {
        "title": "User enumeration via Yoast author sitemap",
        "severity": "INFO",
        "description": "The Yoast SEO author sitemap (/author-sitemap.xml) exposes usernames.",
        "remediation": "Disable author sitemaps in Yoast SEO settings.",
        "references": [],
        "remediation_id": "REM-USR-005",
    },
    # ------------------------------------------------------------------ #
    # Brute force module findings (AC-12, AC-14)                         #
    # ------------------------------------------------------------------ #
    "PC-BRU-001": {
        "title": "Valid WordPress credentials found via brute force",
        "severity": "CRITICAL",
        "description": "Brute force attack found valid credential pairs for WordPress login.",
        "remediation": "Change all found passwords immediately. Enable 2FA. Implement account lockout.",
        "references": ["https://wordpress.org/support/article/brute-force-attacks/"],
        "remediation_id": "REM-BRU-001",
    },
    "PC-BRU-002": {
        "title": "2FA detected on WordPress login",
        "severity": "INFO",
        "description": "Two-factor authentication was detected on the login page.",
        "remediation": "Keep 2FA enabled and enforce it for all users.",
        "references": [],
        "remediation_id": "REM-BRU-002",
    },
    "PC-BRU-003": {
        "title": "Brute force stopped or skipped",
        "severity": "INFO",
        "description": "Brute force was stopped due to rate limiting or skipped due to no usernames found.",
        "remediation": "Rate limiting is a positive control. Ensure it is properly configured.",
        "references": [],
        "remediation_id": "REM-BRU-003",
    },
    "PC-BRU-004": {
        "title": "Brute force completed — no valid credentials found",
        "severity": "INFO",
        "description": "Brute force completed without finding valid credentials.",
        "remediation": "Continue enforcing strong password policies and account lockout.",
        "references": [],
        "remediation_id": "REM-BRU-004",
    },
    "PC-BRU-007": {
        "title": "Brute force stopped — rate limiting / circuit breaker exhausted",
        "severity": "INFO",
        "description": (
            "The target rate-limited login attempts. If three or more consecutive 429 / "
            "connection-reset responses were received, the adaptive circuit breaker activated "
            "and waited up to 60 s (10 s + 20 s + 30 s back-off windows) before giving up. "
            "evidence fields: total_wait_seconds (0 for immediate stop), attempts_made."
        ),
        "remediation": "Rate limiting is a positive security control. Ensure it is properly configured.",
        "references": [],
        "remediation_id": "REM-BRU-007",
    },
    "PC-BRU-008": {
        "title": "Brute force enabled but no wordlist provided",
        "severity": "INFO",
        "description": (
            "Brute force was enabled (--brute-force) but no password source was configured. "
            "Use --brute-force-defaults to activate the built-in wordlist, "
            "or --brute-force-wordlist <path> to supply an external one."
        ),
        "remediation": "Supply a wordlist via --brute-force-defaults or --brute-force-wordlist.",
        "references": [],
        "remediation_id": "REM-BRU-008",
    },
    # ------------------------------------------------------------------ #
    # TimThumb module findings (AC-7)                                     #
    # ------------------------------------------------------------------ #
    "PC-TTH-001": {
        "title": "TimThumb script is publicly accessible",
        "severity": "HIGH",
        "description": "A timthumb.php script was found accessible at the target. TimThumb is an outdated image-resizing library with a long history of critical vulnerabilities including remote code execution.",
        "remediation": "Remove timthumb.php from the server. Modern WordPress themes use native image handling and do not require TimThumb.",
        "references": [
            "https://blog.sucuri.net/2014/06/timthumb-zero-day-exploit-found-vulnerability-in-webshot.html",
            "https://nvd.nist.gov/vuln/search/results?query=timthumb",
        ],
        "remediation_id": "REM-TTH-001",
    },
    "PC-TTH-002": {
        "title": "TimThumb version below 2.8.14 (vulnerable)",
        "severity": "CRITICAL",
        "description": "The detected TimThumb version is older than 2.8.14, the last patched release. This version is vulnerable to multiple critical exploits including remote code execution via webshot and arbitrary file inclusion.",
        "remediation": "Remove timthumb.php immediately. If the theme/plugin requires it, update to a version that uses a patched TimThumb or native WordPress image handling.",
        "references": ["https://nvd.nist.gov/vuln/search/results?query=timthumb"],
        "remediation_id": "REM-TTH-002",
    },
    "PC-TTH-003": {
        "title": "TimThumb found inside plugin directory",
        "severity": "HIGH",
        "description": "A timthumb.php file was found inside a WordPress plugin directory. Plugins bundling TimThumb are a known attack vector for compromising WordPress sites.",
        "remediation": "Update or remove the plugin that bundles TimThumb. Contact the plugin author to request removal of the TimThumb dependency.",
        "references": [
            "https://blog.sucuri.net/2014/06/timthumb-zero-day-exploit-found-vulnerability-in-webshot.html"
        ],
        "remediation_id": "REM-TTH-003",
    },
    # ------------------------------------------------------------------ #
    # Emergency Scripts module findings (AC-8)                            #
    # ------------------------------------------------------------------ #
    "PC-EMRG-001": {
        "title": "Emergency script /emergency.php is accessible",
        "severity": "HIGH",
        "description": "/emergency.php is publicly accessible and contains PHP signatures (password reset, form elements) suggesting it is an emergency WordPress administration script. Such scripts bypass normal authentication and are a critical security risk.",
        "remediation": "Remove /emergency.php immediately after use. Never leave emergency scripts accessible on production servers.",
        "references": ["https://wordpress.org/support/article/hardening-wordpress/"],
        "remediation_id": "REM-EMRG-001",
    },
    "PC-EMRG-002": {
        "title": "Emergency script /wp-emergency.php is accessible",
        "severity": "HIGH",
        "description": "/wp-emergency.php is publicly accessible and contains PHP signatures suggesting it is an emergency WordPress administration script that bypasses normal authentication.",
        "remediation": "Remove /wp-emergency.php immediately after use.",
        "references": ["https://wordpress.org/support/article/hardening-wordpress/"],
        "remediation_id": "REM-EMRG-002",
    },
    "PC-EMRG-003": {
        "title": "Emergency script /reset.php is accessible",
        "severity": "HIGH",
        "description": "/reset.php is publicly accessible and contains PHP signatures suggesting it is a WordPress password reset or emergency access script.",
        "remediation": "Remove /reset.php immediately after use.",
        "references": ["https://wordpress.org/support/article/hardening-wordpress/"],
        "remediation_id": "REM-EMRG-003",
    },
    "PC-EMRG-004": {
        "title": "Emergency script /pw-reset.php is accessible",
        "severity": "HIGH",
        "description": "/pw-reset.php is publicly accessible and contains PHP signatures suggesting it is a WordPress password reset script that bypasses normal authentication.",
        "remediation": "Remove /pw-reset.php immediately after use.",
        "references": ["https://wordpress.org/support/article/hardening-wordpress/"],
        "remediation_id": "REM-EMRG-004",
    },
    "PC-EMRG-005": {
        "title": "Emergency script /emergency-reset.php is accessible",
        "severity": "HIGH",
        "description": "/emergency-reset.php is publicly accessible and contains PHP signatures suggesting it is an emergency WordPress reset script that bypasses normal authentication.",
        "remediation": "Remove /emergency-reset.php immediately after use.",
        "references": ["https://wordpress.org/support/article/hardening-wordpress/"],
        "remediation_id": "REM-EMRG-005",
    },
    # ------------------------------------------------------------------ #
    # Brute module findings (AC-9)                                        #
    # ------------------------------------------------------------------ #
    "PC-BRUTE-001": {
        "title": "Valid credentials found via XML-RPC brute force",
        "severity": "CRITICAL",
        "description": "Brute force attack via the XML-RPC endpoint found valid credential pairs. An attacker can use these credentials to gain full administrative access.",
        "remediation": "Change found passwords immediately. Disable XML-RPC if not needed. Enable 2FA and implement account lockout.",
        "references": [
            "https://kinsta.com/blog/xmlrpc-php/#xmlrpc-brute-force-attacks",
            "https://wordpress.org/support/article/brute-force-attacks/",
        ],
        "remediation_id": "REM-BRUTE-001",
    },
    "PC-BRUTE-002": {
        "title": "Valid credentials found via wp-login.php brute force",
        "severity": "CRITICAL",
        "description": "Brute force attack via wp-login.php found valid credential pairs. An attacker can use these credentials to gain full administrative access.",
        "remediation": "Change found passwords immediately. Enable 2FA. Implement account lockout and IP-based rate limiting.",
        "references": ["https://wordpress.org/support/article/brute-force-attacks/"],
        "remediation_id": "REM-BRUTE-002",
    },
    "PC-BRUTE-003": {
        "title": "No brute force protection detected on login endpoints",
        "severity": "HIGH",
        "description": "Multiple credential attempts were made against WordPress login endpoints without triggering any rate limiting or blocking. The site lacks brute force protection.",
        "remediation": "Implement account lockout and rate limiting. Use a security plugin such as Wordfence or limit-login-attempts-reloaded. Disable XML-RPC if not needed.",
        "references": [
            "https://wordpress.org/support/article/brute-force-attacks/",
            "https://kinsta.com/blog/wordpress-login-page/#how-to-protect-your-wordpress-login-page",
        ],
        "remediation_id": "REM-BRUTE-003",
    },
    "PC-BRUTE-004": {
        "title": "Brute force protection confirmed",
        "severity": "INFO",
        "description": "Rate limiting or blocking was detected on WordPress login endpoints after repeated authentication attempts. Active brute force protection is in place.",
        "remediation": "No action required. Rate limiting is a positive security control. Ensure it is properly configured.",
        "references": [],
        "remediation_id": "REM-BRUTE-004",
    },
    # ------------------------------------------------------------------ #
    # WP Hardening module findings (AC-10)                                #
    # ------------------------------------------------------------------ #
    "PC-WPH-001": {
        "title": "WordPress version is outdated",
        "severity": "MEDIUM",
        "description": "The detected WordPress version is older than the known latest version (6.8.1). Outdated WordPress installations may be vulnerable to publicly disclosed security issues.",
        "remediation": "Update WordPress to the latest version immediately via Dashboard > Updates or WP-CLI: wp core update.",
        "references": [
            "https://wordpress.org/news/category/releases/",
            "https://wordpress.org/support/article/updating-wordpress/",
        ],
        "remediation_id": "REM-WPH-001",
    },
}


@app.command("explain")
def explain(
    finding_id: str = typer.Argument(..., help="Finding ID (e.g. PC-XMLRPC-002)"),
    lang: Optional[str] = typer.Option(None, "--lang", "-L", help="Language for output (en, es).", envvar="PLECOST_LANG"),
) -> None:
    """Show detailed information and remediation for a finding ID."""
    if lang:
        set_language(lang)
    from rich.panel import Panel
    fid = finding_id.upper()
    if fid not in _FINDINGS_REGISTRY:
        console.print(f"[red]Unknown finding ID: {fid}[/red]")
        console.print("[dim]Run 'plecost modules list' to see available modules.[/dim]")
        raise typer.Exit(1)
    info = _FINDINGS_REGISTRY[fid]
    key = _finding_key(fid)
    title = t(f"findings.{key}.title")
    description = t(f"findings.{key}.description")
    remediation = t(f"findings.{key}.remediation")
    sev_colors = {"CRITICAL": "red", "HIGH": "orange3", "MEDIUM": "yellow", "LOW": "cyan", "INFO": "white"}
    color = sev_colors.get(info["severity"], "white")
    console.print(Panel(
        f"[bold]{title}[/bold]\n\n"
        f"[dim]{t('cli.explain.severity')}:[/dim] [{color}]{info['severity']}[/{color}]\n"
        f"[dim]{t('cli.explain.remediation_id')}:[/dim] {info['remediation_id']}\n\n"
        f"[bold]{t('cli.explain.description')}:[/bold]\n{description}\n\n"
        f"[bold]{t('cli.explain.remediation')}:[/bold]\n[green]{remediation}[/green]" +
        ("\n\n[bold]{refs}:[/bold]\n".format(refs=t('cli.explain.references')) + "\n".join(f"- {r}" for r in info['references']) if info['references'] else ""),
        title=f"[bold]{fid}[/bold]",
        border_style=color,
    ))


if __name__ == "__main__":
    app()
