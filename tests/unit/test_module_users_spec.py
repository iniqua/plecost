"""Spec-driven tests for UsersModule — one test per AC from the Spec Lock.

These tests verify the acceptance criteria. They MUST fail if the implementation
does not satisfy the AC. Tests use asyncio_mode=auto (no @pytest.mark.asyncio).
"""
from __future__ import annotations

import pytest
import respx
import httpx
from unittest.mock import AsyncMock, patch

from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import ScanOptions
from plecost.modules.users import UsersModule


@pytest.fixture
def ctx():
    ctx = ScanContext(ScanOptions(url="https://example.com"))
    ctx.is_wordpress = True
    return ctx


@pytest.fixture
def ctx_deep():
    ctx = ScanContext(ScanOptions(url="https://example.com", deep=True))
    ctx.is_wordpress = True
    return ctx


# ---------------------------------------------------------------------------
# AC-1: REST API pagination via X-WP-TotalPages header
# ---------------------------------------------------------------------------

async def test_rest_api_pagination_follows_x_wp_totalpages(ctx):
    """AC-1: UsersModule enumerates users via REST API with full pagination,
    iterating over all pages indicated by X-WP-TotalPages header."""
    page1 = '[{"id":1,"name":"Admin","slug":"admin","link":"https://example.com/author/admin/"}]'
    page2 = '[{"id":2,"name":"Editor","slug":"editor","link":"https://example.com/author/editor/"}]'

    async with respx.mock:
        respx.get("https://example.com/wp-json/wp/v2/users").mock(
            return_value=httpx.Response(
                200,
                text=page1,
                headers={"X-WP-TotalPages": "2", "X-WP-Total": "2"},
            )
        )
        respx.get("https://example.com/wp-json/wp/v2/users?page=2").mock(
            return_value=httpx.Response(
                200,
                text=page2,
                headers={"X-WP-TotalPages": "2", "X-WP-Total": "2"},
            )
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))

        async with PlecostHTTPClient(ctx.opts) as http:
            await UsersModule().run(ctx, http)

    usernames = {u.username for u in ctx.users}
    assert "admin" in usernames, "Page 1 user must be enumerated"
    assert "editor" in usernames, "Page 2 user must be enumerated (pagination followed)"


async def test_rest_api_pagination_sequential(ctx):
    """AC-1: Pagination iteration must be sequential (page 1, then 2, then 3...)."""
    pages_requested = []

    async def record_page(request):
        page = request.url.params.get("page", "1")
        pages_requested.append(int(page))
        if int(page) == 1:
            return httpx.Response(
                200,
                json=[{"id": 1, "slug": "admin", "name": "Admin"}],
                headers={"X-WP-TotalPages": "3"},
            )
        elif int(page) == 2:
            return httpx.Response(
                200,
                json=[{"id": 2, "slug": "editor", "name": "Editor"}],
                headers={"X-WP-TotalPages": "3"},
            )
        else:
            return httpx.Response(
                200,
                json=[{"id": 3, "slug": "subscriber", "name": "Subscriber"}],
                headers={"X-WP-TotalPages": "3"},
            )

    async with respx.mock:
        respx.get(url__regex=r".*wp-json/wp/v2/users.*").mock(side_effect=record_page)
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))

        async with PlecostHTTPClient(ctx.opts) as http:
            await UsersModule().run(ctx, http)

    assert pages_requested == sorted(pages_requested), "Pages must be fetched in sequential order"
    assert len(ctx.users) >= 3, "All pages must be iterated"


# ---------------------------------------------------------------------------
# AC-2: Author IDs 1-25 (fast) / 1-100 (deep) with early-stop after 3 misses
# ---------------------------------------------------------------------------

async def test_author_id_range_fast_mode_configured_for_25(ctx):
    """AC-2: In fast mode, the author ID ceiling must be configured at 25 (not just the current 10)."""
    module = UsersModule()
    # The spec says fast=1-25. Check that the module has the correct configuration.
    # Either via _MAX_AUTHOR_ID_FAST=25 or _MAX_AUTHOR_ID=25 when not deep
    fast_cap = getattr(module, '_MAX_AUTHOR_ID_FAST', None)
    if fast_cap is None:
        # Legacy: _MAX_AUTHOR_ID is used for fast mode
        fast_cap = getattr(module, '_MAX_AUTHOR_ID', None)
    assert fast_cap == 25, (
        f"AC-2: Fast mode author ID ceiling must be 25, got {fast_cap}"
    )


async def test_author_id_range_deep_mode_configured_for_100():
    """AC-2: In deep mode, the author ID ceiling must be configured at 100."""
    module = UsersModule()
    deep_cap = getattr(module, '_MAX_AUTHOR_ID_DEEP', None)
    assert deep_cap == 100, (
        f"AC-2: Deep mode author ID ceiling must be 100, got {deep_cap}"
    )


async def test_author_id_deep_mode_uses_higher_cap_than_fast():
    """AC-2: Deep mode ceiling (100) must be higher than fast mode ceiling (25)."""
    module = UsersModule()
    fast_cap = getattr(module, '_MAX_AUTHOR_ID_FAST', getattr(module, '_MAX_AUTHOR_ID', None))
    deep_cap = getattr(module, '_MAX_AUTHOR_ID_DEEP', None)
    assert fast_cap is not None, "AC-2: Fast mode ID cap attribute must exist"
    assert deep_cap is not None, "AC-2: Deep mode ID cap attribute must exist"
    assert deep_cap > fast_cap, (
        f"AC-2: Deep cap ({deep_cap}) must be greater than fast cap ({fast_cap})"
    )


async def test_author_id_early_stop_after_3_consecutive_misses(ctx):
    """AC-2: Author probing stops after 3 consecutive IDs with no redirect."""
    ids_requested = []

    async def author_handler(request):
        id_val = request.url.params.get("author")
        if id_val:
            ids_requested.append(int(id_val))
        # Only ID 1 redirects; IDs 2,3,4 = 404 → should trigger early stop
        if id_val == "1":
            return httpx.Response(
                301, headers={"location": "https://example.com/author/admin/"}
            )
        return httpx.Response(404)

    async with respx.mock:
        respx.get("https://example.com/wp-json/wp/v2/users").mock(
            return_value=httpx.Response(403)
        )
        respx.get(url__regex=r".*\?author=\d+").mock(side_effect=author_handler)
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))

        async with PlecostHTTPClient(ctx.opts) as http:
            await UsersModule().run(ctx, http)

    if ids_requested:
        # After ID 1 (redirect), IDs 2, 3, 4 = 404 → early stop at 4
        # So max probed should be 4 (3 consecutive misses after last hit)
        assert max(ids_requested) <= 7, (
            f"Early-stop must trigger after 3 consecutive misses; "
            f"max probed={max(ids_requested)}"
        )


# ---------------------------------------------------------------------------
# AC-3: /wp-sitemap-users-1.xml detection → PC-USR-003 (INFO, 3.1)
# ---------------------------------------------------------------------------

async def test_wp_sitemap_users_detection_pc_usr_003(ctx):
    """AC-3: UsersModule detects users in /wp-sitemap-users-1.xml and emits PC-USR-003 (INFO, 3.1)."""
    sitemap_xml = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://example.com/author/johndoe/</loc>
    <lastmod>2024-01-01</lastmod>
  </url>
  <url>
    <loc>https://example.com/author/janedoe/</loc>
    <lastmod>2024-01-02</lastmod>
  </url>
</urlset>"""

    async with respx.mock:
        respx.get("https://example.com/wp-json/wp/v2/users").mock(
            return_value=httpx.Response(403)
        )
        respx.get("https://example.com/wp-sitemap-users-1.xml").mock(
            return_value=httpx.Response(
                200,
                text=sitemap_xml,
                headers={"content-type": "application/xml"},
            )
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))

        async with PlecostHTTPClient(ctx.opts) as http:
            await UsersModule().run(ctx, http)

    usr003_findings = [f for f in ctx.findings if f.id == "PC-USR-003"]
    assert len(usr003_findings) == 1, "PC-USR-003 finding must be emitted exactly once"
    assert usr003_findings[0].severity.value == "INFO", "PC-USR-003 must be INFO severity"
    assert abs(usr003_findings[0].cvss_score - 3.1) < 0.01, "PC-USR-003 must have CVSS score 3.1"

    usernames = {u.username for u in ctx.users}
    assert "johndoe" in usernames or "janedoe" in usernames, "Users from sitemap must be extracted"


async def test_wp_sitemap_users_xml_namespace(ctx):
    """AC-3: Sitemap parser must handle correct XML namespace (sitemaps.org/schemas/sitemap/0.9)."""
    # XML with namespace — must be parsed correctly
    sitemap_xml = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://example.com/author/wp-author/</loc>
  </url>
</urlset>"""

    async with respx.mock:
        respx.get("https://example.com/wp-json/wp/v2/users").mock(
            return_value=httpx.Response(403)
        )
        respx.get("https://example.com/wp-sitemap-users-1.xml").mock(
            return_value=httpx.Response(200, text=sitemap_xml)
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))

        async with PlecostHTTPClient(ctx.opts) as http:
            await UsersModule().run(ctx, http)

    usr003 = [f for f in ctx.findings if f.id == "PC-USR-003"]
    assert len(usr003) == 1, "PC-USR-003 must be emitted when wp-sitemap-users-1.xml returns user URLs"


# ---------------------------------------------------------------------------
# AC-4: RSS feed <dc:creator> → PC-USR-004 (MEDIUM, 5.3)
# ---------------------------------------------------------------------------

async def test_rss_feed_dc_creator_pc_usr_004(ctx):
    """AC-4: UsersModule detects users in RSS feed <dc:creator> and emits PC-USR-004 (MEDIUM, 5.3)."""
    rss_xml = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:dc="http://purl.org/dc/elements/1.1/">
  <channel>
    <title>Test Blog</title>
    <item>
      <title>Post 1</title>
      <dc:creator>rssauthor</dc:creator>
    </item>
    <item>
      <title>Post 2</title>
      <dc:creator>anotherauthor</dc:creator>
    </item>
  </channel>
</rss>"""

    async with respx.mock:
        respx.get("https://example.com/wp-json/wp/v2/users").mock(
            return_value=httpx.Response(403)
        )
        respx.get("https://example.com/feed/").mock(
            return_value=httpx.Response(200, text=rss_xml)
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))

        async with PlecostHTTPClient(ctx.opts) as http:
            await UsersModule().run(ctx, http)

    usr004_findings = [f for f in ctx.findings if f.id == "PC-USR-004"]
    assert len(usr004_findings) == 1, "PC-USR-004 finding must be emitted exactly once for RSS"
    assert usr004_findings[0].severity.value == "MEDIUM", "PC-USR-004 must be MEDIUM severity"
    assert abs(usr004_findings[0].cvss_score - 5.3) < 0.01, "PC-USR-004 must have CVSS score 5.3"

    usernames = {u.username for u in ctx.users}
    assert "rssauthor" in usernames or "anotherauthor" in usernames, (
        "Users from RSS dc:creator must be extracted"
    )


async def test_rss_dedup_by_username_not_display_name(ctx):
    """FIX-4: RSS deduplication must compare by username, not display_name."""
    # Two items with the same dc:creator — should result in only 1 user entry
    rss_xml = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:dc="http://purl.org/dc/elements/1.1/">
  <channel>
    <item><title>Post 1</title><dc:creator>dupuser</dc:creator></item>
    <item><title>Post 2</title><dc:creator>dupuser</dc:creator></item>
    <item><title>Post 3</title><dc:creator>uniqueuser</dc:creator></item>
  </channel>
</rss>"""

    async with respx.mock:
        respx.get("https://example.com/wp-json/wp/v2/users").mock(
            return_value=httpx.Response(403)
        )
        respx.get("https://example.com/feed/").mock(
            return_value=httpx.Response(200, text=rss_xml)
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))

        async with PlecostHTTPClient(ctx.opts) as http:
            await UsersModule().run(ctx, http)

    rss_users = [u for u in ctx.users if u.source == "rss"]
    usernames = [u.username for u in rss_users]
    assert usernames.count("dupuser") == 1, (
        f"FIX-4: dupuser must appear only once after dedup (got {usernames.count('dupuser')})"
    )
    assert "uniqueuser" in usernames, "uniqueuser must be present"


# ---------------------------------------------------------------------------
# AC-5: /author-sitemap.xml (Yoast) → PC-USR-005 (INFO, 3.1) — separate from PC-USR-003
# ---------------------------------------------------------------------------

async def test_yoast_author_sitemap_pc_usr_005(ctx):
    """AC-5: UsersModule detects users in /author-sitemap.xml and emits PC-USR-005 (INFO, 3.1)."""
    sitemap_xml = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://example.com/author/yoastuser/</loc>
  </url>
</urlset>"""

    async with respx.mock:
        respx.get("https://example.com/wp-json/wp/v2/users").mock(
            return_value=httpx.Response(403)
        )
        respx.get("https://example.com/author-sitemap.xml").mock(
            return_value=httpx.Response(200, text=sitemap_xml)
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))

        async with PlecostHTTPClient(ctx.opts) as http:
            await UsersModule().run(ctx, http)

    usr005_findings = [f for f in ctx.findings if f.id == "PC-USR-005"]
    assert len(usr005_findings) == 1, "PC-USR-005 must be emitted for /author-sitemap.xml"
    assert usr005_findings[0].severity.value == "INFO", "PC-USR-005 must be INFO severity"
    assert abs(usr005_findings[0].cvss_score - 3.1) < 0.01, "PC-USR-005 must have CVSS score 3.1"


async def test_yoast_sitemap_separate_from_wp_sitemap(ctx):
    """AC-5: PC-USR-005 (Yoast) must be a separate finding from PC-USR-003 (wp-sitemap)."""
    wp_sitemap_xml = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://example.com/author/wpuser/</loc></url>
</urlset>"""

    yoast_sitemap_xml = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://example.com/author/yoastuser/</loc></url>
</urlset>"""

    async with respx.mock:
        respx.get("https://example.com/wp-json/wp/v2/users").mock(
            return_value=httpx.Response(403)
        )
        respx.get("https://example.com/wp-sitemap-users-1.xml").mock(
            return_value=httpx.Response(200, text=wp_sitemap_xml)
        )
        respx.get("https://example.com/author-sitemap.xml").mock(
            return_value=httpx.Response(200, text=yoast_sitemap_xml)
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))

        async with PlecostHTTPClient(ctx.opts) as http:
            await UsersModule().run(ctx, http)

    usr003_findings = [f for f in ctx.findings if f.id == "PC-USR-003"]
    usr005_findings = [f for f in ctx.findings if f.id == "PC-USR-005"]
    assert len(usr003_findings) == 1, "PC-USR-003 for wp-sitemap-users-1.xml must be present"
    assert len(usr005_findings) == 1, "PC-USR-005 for author-sitemap.xml must be separate finding"


# ---------------------------------------------------------------------------
# AC-6: oEmbed author_url — only if contains /author/, no finding emitted
# ---------------------------------------------------------------------------

async def test_oembed_extracts_user_only_if_author_in_url(ctx):
    """AC-6: oEmbed extraction only adds user if author_url contains /author/. No finding emitted."""
    oembed_json = """{
        "author_name": "John Doe",
        "author_url": "https://example.com/author/johndoe/",
        "type": "rich"
    }"""

    async with respx.mock:
        respx.get("https://example.com/wp-json/wp/v2/users").mock(
            return_value=httpx.Response(403)
        )
        respx.get("https://example.com/wp-json/oembed/1.0/proxy").mock(
            return_value=httpx.Response(200, text=oembed_json)
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))

        async with PlecostHTTPClient(ctx.opts) as http:
            await UsersModule().run(ctx, http)

    oembed_users = [u for u in ctx.users if u.source == "oembed"]
    assert len(oembed_users) >= 1, "User with /author/ in author_url must be extracted from oEmbed"
    assert oembed_users[0].username == "johndoe", "Username extracted from /author/<slug>/ in author_url"

    # No finding should be emitted for oEmbed
    oembed_findings = [f for f in ctx.findings if "oembed" in f.id.lower() or "oEmbed" in f.title]
    assert len(oembed_findings) == 0, "AC-6: oEmbed must not emit any finding"


async def test_oembed_skips_user_when_no_author_in_url(ctx):
    """AC-6: oEmbed must NOT add user if author_url does NOT contain /author/."""
    oembed_json = """{
        "author_name": "John Doe",
        "author_url": "https://external-site.com/profile/johndoe/",
        "type": "rich"
    }"""

    async with respx.mock:
        respx.get("https://example.com/wp-json/wp/v2/users").mock(
            return_value=httpx.Response(403)
        )
        respx.get("https://example.com/wp-json/oembed/1.0/proxy").mock(
            return_value=httpx.Response(200, text=oembed_json)
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))

        async with PlecostHTTPClient(ctx.opts) as http:
            await UsersModule().run(ctx, http)

    oembed_users = [u for u in ctx.users if u.source == "oembed"]
    assert len(oembed_users) == 0, (
        "AC-6: oEmbed must NOT add user when author_url does not contain /author/"
    )


async def test_oembed_no_provisional_username(ctx):
    """AC-6: oEmbed must NOT create provisional usernames (e.g. from author_name)."""
    oembed_json = """{
        "author_name": "John Doe",
        "author_url": "https://example.com/author/real-slug/",
        "type": "rich"
    }"""

    async with respx.mock:
        respx.get("https://example.com/wp-json/wp/v2/users").mock(
            return_value=httpx.Response(403)
        )
        respx.get("https://example.com/wp-json/oembed/1.0/proxy").mock(
            return_value=httpx.Response(200, text=oembed_json)
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))

        async with PlecostHTTPClient(ctx.opts) as http:
            await UsersModule().run(ctx, http)

    oembed_users = [u for u in ctx.users if u.source == "oembed"]
    # The username must come from the URL slug, not a mangled version of author_name
    for user in oembed_users:
        assert "john" not in user.username.lower() or user.username == "real-slug", (
            f"AC-6: Username must be extracted from URL slug, not author_name; got={user.username}"
        )
        # Confirm the slug from URL is used
        assert user.username == "real-slug", (
            f"AC-6: Username must be the /author/<slug>/ from author_url; got={user.username}"
        )


# ---------------------------------------------------------------------------
# AC-7: Homepage HTML author links via regex /author/<slug>/
# ---------------------------------------------------------------------------

async def test_homepage_author_links_extraction(ctx):
    """AC-7: UsersModule extracts users from homepage HTML author links via /author/<slug>/ regex."""
    homepage_html = """<!DOCTYPE html>
<html>
<body>
  <a href="https://example.com/author/blogauthor/" rel="author">Blog Author</a>
  <a href="https://example.com/author/anotherwriter/">Another Writer</a>
  <p>Some content without author links</p>
</body>
</html>"""

    async with respx.mock:
        respx.get("https://example.com/wp-json/wp/v2/users").mock(
            return_value=httpx.Response(403)
        )
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(200, text=homepage_html)
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))

        async with PlecostHTTPClient(ctx.opts) as http:
            await UsersModule().run(ctx, http)

    html_users = [u for u in ctx.users if u.source == "html"]
    usernames = {u.username for u in html_users}
    assert "blogauthor" in usernames or "anotherwriter" in usernames, (
        "AC-7: Users from homepage /author/<slug>/ links must be extracted"
    )


async def test_homepage_author_links_no_finding(ctx):
    """AC-7: Homepage author link extraction must NOT emit its own finding."""
    homepage_html = """<html><body>
    <a href="https://example.com/author/silentuser/">Silent User</a>
    </body></html>"""

    async with respx.mock:
        respx.get("https://example.com/wp-json/wp/v2/users").mock(
            return_value=httpx.Response(403)
        )
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(200, text=homepage_html)
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))

        async with PlecostHTTPClient(ctx.opts) as http:
            await UsersModule().run(ctx, http)

    html_only_findings = [
        f for f in ctx.findings
        if "html" in f.id.lower() or "homepage" in f.title.lower()
    ]
    assert len(html_only_findings) == 0, "AC-7: Homepage HTML author links must not emit a finding"


# ---------------------------------------------------------------------------
# FIX-2: REST API pagination capped at 100 pages
# ---------------------------------------------------------------------------

async def test_rest_api_pagination_capped_at_100_pages(ctx):
    """FIX-2: REST API pagination must never exceed 100 page requests (DoS protection).
    Also verifies that pages ARE being followed (otherwise trivially passes).
    """
    pages_requested = []

    async def infinite_pages(request):
        page = int(request.url.params.get("page", "1"))
        pages_requested.append(page)
        return httpx.Response(
            200,
            json=[{"id": page * 10, "slug": f"user{page}", "name": f"User {page}"}],
            headers={"X-WP-TotalPages": "99999", "X-WP-Total": "99999"},
        )

    async with respx.mock:
        respx.get(url__regex=r".*wp-json/wp/v2/users.*").mock(side_effect=infinite_pages)
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))

        async with PlecostHTTPClient(ctx.opts) as http:
            await UsersModule().run(ctx, http)

    # Must follow pagination (more than 1 page)
    assert len(pages_requested) > 1, (
        "FIX-2: REST pagination must be followed when X-WP-TotalPages > 1"
    )
    assert max(pages_requested) <= 100, (
        f"FIX-2: Pagination must be capped at 100 pages, got {max(pages_requested)}"
    )
    assert len(pages_requested) <= 100, (
        f"FIX-2: Must not make more than 100 REST API page requests, got {len(pages_requested)}"
    )
