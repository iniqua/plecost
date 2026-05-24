from __future__ import annotations
import json
import re
import asyncio
import xml.etree.ElementTree as ET
from typing import Any
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import Finding, Severity, User
from plecost.modules.base import ScanModule

# XML namespace for WordPress sitemaps
SITEMAP_NS = "http://www.sitemaps.org/schemas/sitemap/0.9"
# Dublin Core namespace for RSS feeds
DC_NS = "http://purl.org/dc/elements/1.1/"


class UsersModule(ScanModule):
    name = "users"
    depends_on = ["fingerprint"]

    async def run(self, ctx: ScanContext, http: PlecostHTTPClient) -> None:
        if not ctx.is_wordpress and not ctx.opts.force:
            return
        await asyncio.gather(
            self._rest_api_paginated(ctx, http),
            self._author_archives(ctx, http),
            self._wp_sitemap_users(ctx, http),
            self._rss_feed(ctx, http),
            self._yoast_author_sitemap(ctx, http),
            self._oembed_user(ctx, http),
            self._html_author_links(ctx, http),
            return_exceptions=True,
        )

    # ------------------------------------------------------------------ #
    # AC-1: REST API with full X-WP-TotalPages pagination                 #
    # ------------------------------------------------------------------ #
    async def _rest_api_paginated(self, ctx: ScanContext, http: PlecostHTTPClient) -> None:
        try:
            r = await http.get(f"{ctx.url}/wp-json/wp/v2/users?per_page=100&page=1")
            if r.status_code != 200:
                return
            try:
                users_data = json.loads(r.text)
            except json.JSONDecodeError:
                return
            if not isinstance(users_data, list) or not users_data:
                return

            all_users: list[dict[str, Any]] = list(users_data)

            # Paginate through remaining pages (AC-1: sequential iteration)
            # F-2: cap total_pages to avoid unbounded requests from malicious server
            total_pages = min(int(r.headers.get("X-WP-TotalPages", 1)), 100)
            for page in range(2, total_pages + 1):
                try:
                    rp = await http.get(f"{ctx.url}/wp-json/wp/v2/users?per_page=100&page={page}")
                    if rp.status_code != 200:
                        break
                    page_data = json.loads(rp.text)
                    if not isinstance(page_data, list):
                        break
                    all_users.extend(page_data)
                except Exception:
                    break

            for u in all_users:
                slug = u.get("slug", "")
                if slug and not any(
                    ex.username.lower() == slug.lower() for ex in ctx.users
                ):
                    ctx.add_user(User(
                        id=u.get("id"),
                        username=slug,
                        display_name=u.get("name"),
                        source="rest_api",
                    ))

            users_formatted = "\n".join(
                f"  • [id:{u.get('id')}] {u.get('name', '?')} (@{u.get('slug', '?')}) — {u.get('link', '')}"
                for u in all_users
            )
            ctx.add_finding(Finding(
                id="PC-USR-001", remediation_id="REM-USR-001",
                title="User enumeration via REST API",
                severity=Severity.MEDIUM,
                description=f"REST API exposes {len(all_users)} user(s): {', '.join(u.get('slug', '?') for u in all_users)}",
                evidence={"url": f"{ctx.url}/wp-json/wp/v2/users", "users": users_formatted},
                remediation="Restrict REST API user endpoint. Add to functions.php: add_filter('rest_endpoints', function($e){ unset($e['/wp/v2/users']); return $e; });",
                references=["https://www.wordfence.com/learn/wordpress-rest-api/"],
                cvss_score=5.3, module=self.name
            ))
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    # AC-2: Author archives ID probing — 25 (fast) / 100 (deep)          #
    #        Early-stop after 3 consecutive IDs without redirect          #
    # ------------------------------------------------------------------ #
    async def _author_archives(self, ctx: ScanContext, http: PlecostHTTPClient) -> None:
        max_id = 100 if ctx.opts.deep else 25
        found_users: list[str] = []
        consecutive_misses = 0

        for i in range(1, max_id + 1):
            try:
                r = await http.get(f"{ctx.url}/?author={i}", follow_redirects=False)
                if r.status_code in (301, 302):
                    location = r.headers.get("location", "")
                    if m := re.search(r'/author/([^/]+)/', location):
                        username = m.group(1)
                        consecutive_misses = 0
                        found_users.append(username)
                        if not any(u.username.lower() == username.lower() for u in ctx.users):
                            ctx.add_user(User(
                                id=i,
                                username=username,
                                display_name=None,
                                source="author_archive",
                            ))
                    else:
                        consecutive_misses += 1
                else:
                    consecutive_misses += 1
            except Exception:
                consecutive_misses += 1

            if consecutive_misses >= 3:
                break

        if found_users:
            ctx.add_finding(Finding(
                id="PC-USR-002", remediation_id="REM-USR-002",
                title="User enumeration via author archives",
                severity=Severity.MEDIUM,
                description=f"Author archives expose usernames: {', '.join(found_users)}",
                evidence={"users": "\n".join(f"  • {u}" for u in found_users)},
                remediation="Redirect /?author=N requests to homepage. Add rewrite rules in .htaccess or nginx config.",
                references=[],
                cvss_score=5.3, module=self.name
            ))

    # ------------------------------------------------------------------ #
    # AC-3: /wp-sitemap-users-1.xml  → PC-USR-003 (INFO 3.1)             #
    # ------------------------------------------------------------------ #
    async def _wp_sitemap_users(self, ctx: ScanContext, http: PlecostHTTPClient) -> None:
        try:
            url = f"{ctx.url}/wp-sitemap-users-1.xml"
            r = await http.get(url)
            if r.status_code != 200:
                return
            if len(r.content) > 1_048_576:
                return
            try:
                root = ET.fromstring(r.text)
            except ET.ParseError:
                return

            # Extract author slugs from <loc> URLs using SITEMAP_NS
            slugs: list[str] = []
            for loc_el in root.findall(f"{{{SITEMAP_NS}}}url/{{{SITEMAP_NS}}}loc"):
                loc = (loc_el.text or "").strip()
                if m := re.search(r'/author/([^/]+)/?', loc):
                    slug = m.group(1)
                    slugs.append(slug)
                    if not any(u.username.lower() == slug.lower() for u in ctx.users):
                        ctx.add_user(User(
                            id=None,
                            username=slug,
                            display_name=None,
                            source="wp_sitemap",
                        ))

            if not slugs:
                return

            ctx.add_finding(Finding(
                id="PC-USR-003", remediation_id="REM-USR-003",
                title="User enumeration via WordPress sitemap",
                severity=Severity.INFO,
                description=f"WordPress user sitemap exposes {len(slugs)} username(s).",
                evidence={"url": url, "users": "\n".join(f"  • @{s}" for s in slugs)},
                remediation="Disable the user sitemap: add_filter('wp_sitemaps_add_provider', function($p, $name){ if ($name==='users') return false; return $p; }, 10, 2);",
                references=[],
                cvss_score=3.1, module=self.name
            ))
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    # AC-4: RSS feed <dc:creator>  → PC-USR-004 (MEDIUM 5.3)             #
    # ------------------------------------------------------------------ #
    async def _rss_feed(self, ctx: ScanContext, http: PlecostHTTPClient) -> None:
        try:
            url = f"{ctx.url}/feed/"
            r = await http.get(url)
            if r.status_code != 200:
                return
            if len(r.content) > 1_048_576:
                return
            try:
                root = ET.fromstring(r.text)
            except ET.ParseError:
                return

            creators: list[str] = []
            for creator_el in root.iter(f"{{{DC_NS}}}creator"):
                name = (creator_el.text or "").strip()
                if name and name not in creators:
                    creators.append(name)
                    # dc:creator is display_name, not username — synthesize username
                    # F-4: dedup by synthesized username, not display_name
                    synthesized_username = name.lower().replace(" ", "")
                    if not any(u.username.lower() == synthesized_username.lower() for u in ctx.users):
                        ctx.add_user(User(
                            id=None,
                            username=synthesized_username,
                            display_name=name,
                            source="rss_feed",
                        ))

            if not creators:
                return

            ctx.add_finding(Finding(
                id="PC-USR-004", remediation_id="REM-USR-004",
                title="User enumeration via RSS feed",
                severity=Severity.MEDIUM,
                description=f"RSS feed exposes {len(creators)} author name(s) via dc:creator.",
                evidence={"url": url, "users": "\n".join(f"  • {c}" for c in creators)},
                remediation="Remove author information from RSS feeds by filtering the dc:creator field.",
                references=[],
                cvss_score=5.3, module=self.name
            ))
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    # AC-5: Yoast /author-sitemap.xml  → PC-USR-005 (INFO 3.1)           #
    # ------------------------------------------------------------------ #
    async def _yoast_author_sitemap(self, ctx: ScanContext, http: PlecostHTTPClient) -> None:
        try:
            url = f"{ctx.url}/author-sitemap.xml"
            r = await http.get(url)
            if r.status_code != 200:
                return
            if len(r.content) > 1_048_576:
                return
            try:
                root = ET.fromstring(r.text)
            except ET.ParseError:
                return

            slugs: list[str] = []
            # Yoast uses the same SITEMAP_NS namespace
            for loc_el in root.findall(f"{{{SITEMAP_NS}}}url/{{{SITEMAP_NS}}}loc"):
                loc = (loc_el.text or "").strip()
                if m := re.search(r'/author/([^/]+)/?', loc):
                    slug = m.group(1)
                    slugs.append(slug)
                    if not any(u.username.lower() == slug.lower() for u in ctx.users):
                        ctx.add_user(User(
                            id=None,
                            username=slug,
                            display_name=None,
                            source="yoast_sitemap",
                        ))

            if not slugs:
                return

            ctx.add_finding(Finding(
                id="PC-USR-005", remediation_id="REM-USR-005",
                title="User enumeration via Yoast author sitemap",
                severity=Severity.INFO,
                description=f"Yoast SEO author sitemap exposes {len(slugs)} username(s).",
                evidence={"url": url, "users": "\n".join(f"  • @{s}" for s in slugs)},
                remediation="Disable author sitemaps in Yoast SEO settings: SEO > XML Sitemaps > Author sitemap.",
                references=[],
                cvss_score=3.1, module=self.name
            ))
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    # AC-6: oEmbed — extract username only if author_url has /author/    #
    #        No finding, no provisional username                          #
    # ------------------------------------------------------------------ #
    async def _oembed_user(self, ctx: ScanContext, http: PlecostHTTPClient) -> None:
        try:
            url = f"{ctx.url}/wp-json/oembed/1.0/embed?url={ctx.url}"
            r = await http.get(url)
            if r.status_code != 200:
                return
            try:
                data = json.loads(r.text)
            except json.JSONDecodeError:
                return

            author_url = data.get("author_url", "")
            # AC-6: only extract if /author/ is in the URL
            if "/author/" not in author_url:
                return

            if m := re.search(r'/author/([^/]+)/?', author_url):
                slug = m.group(1)
                if not any(u.username.lower() == slug.lower() for u in ctx.users):
                    ctx.add_user(User(
                        id=None,
                        username=slug,
                        display_name=data.get("author_name"),
                        source="oembed",
                    ))
            # No finding emitted for oEmbed (AC-6)
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    # AC-7: Homepage HTML author links regex /author/<slug>/              #
    #        No finding, deduplication by username (case-insensitive)     #
    # ------------------------------------------------------------------ #
    async def _html_author_links(self, ctx: ScanContext, http: PlecostHTTPClient) -> None:
        try:
            r = await http.get(ctx.url)
            if r.status_code != 200:
                return

            seen: set[str] = set()
            for m in re.finditer(r'/author/([a-zA-Z0-9_.-]+)/', r.text):
                slug = m.group(1)
                slug_lower = slug.lower()
                if slug_lower in seen:
                    continue
                seen.add(slug_lower)
                if not any(u.username.lower() == slug_lower for u in ctx.users):
                    ctx.add_user(User(
                        id=None,
                        username=slug,
                        display_name=None,
                        source="html_author_link",
                    ))
            # No finding emitted for HTML author links (AC-7)
        except Exception:
            pass
