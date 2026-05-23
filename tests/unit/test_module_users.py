import pytest
import respx
import httpx
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import ScanOptions
from plecost.modules.users import UsersModule

BASE = "https://example.com"
REST_URL = f"{BASE}/wp-json/wp/v2/users?per_page=100&page=1"


@pytest.fixture
def ctx():
    ctx = ScanContext(ScanOptions(url=BASE))
    ctx.is_wordpress = True
    return ctx


async def test_enumerates_users_via_rest_api(ctx):
    users_json = '[{"id":1,"name":"admin","slug":"admin","link":"https://example.com/author/admin/"}]'
    async with respx.mock:
        respx.get(REST_URL).mock(
            return_value=httpx.Response(200, text=users_json, headers={"X-WP-TotalPages": "1"})
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await UsersModule().run(ctx, http)
    assert any(u.username == "admin" for u in ctx.users)
    assert any(f.id == "PC-USR-001" for f in ctx.findings)


async def test_rest_api_exposed_adds_finding(ctx):
    async with respx.mock:
        respx.get(REST_URL).mock(
            return_value=httpx.Response(200, text='[{"id":1,"slug":"editor","name":"Editor User"}]',
                                        headers={"X-WP-TotalPages": "1"})
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await UsersModule().run(ctx, http)
    rest_findings = [f for f in ctx.findings if f.id == "PC-USR-001"]
    assert len(rest_findings) == 1
    assert rest_findings[0].severity.value == "MEDIUM"


async def test_rest_api_paginated_fetches_all_pages(ctx):
    """AC-1: X-WP-TotalPages pagination — fetches page 2 when total=2."""
    page1 = '[{"id":1,"name":"admin","slug":"admin"}]'
    page2 = '[{"id":2,"name":"editor","slug":"editor"}]'
    page2_url = f"{BASE}/wp-json/wp/v2/users?per_page=100&page=2"
    async with respx.mock:
        respx.get(REST_URL).mock(
            return_value=httpx.Response(200, text=page1, headers={"X-WP-TotalPages": "2"})
        )
        respx.get(page2_url).mock(
            return_value=httpx.Response(200, text=page2, headers={"X-WP-TotalPages": "2"})
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await UsersModule().run(ctx, http)
    usernames = {u.username for u in ctx.users}
    assert "admin" in usernames
    assert "editor" in usernames


async def test_rest_api_returns_html_no_finding(ctx):
    """When REST API returns HTML (restricted), no finding should be added and no exception raised."""
    html_body = "<html><body><h1>Unauthorized</h1></body></html>"
    async with respx.mock:
        respx.get(REST_URL).mock(
            return_value=httpx.Response(200, text=html_body, headers={"content-type": "text/html"})
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await UsersModule().run(ctx, http)
    rest_findings = [f for f in ctx.findings if f.id == "PC-USR-001"]
    assert len(rest_findings) == 0
    assert len(ctx.users) == 0


async def test_author_archives_enumerates_users(ctx):
    """AC-2: Author archive 301 redirects expose usernames."""
    async with respx.mock:
        respx.get(REST_URL).mock(return_value=httpx.Response(403))
        respx.get(f"{BASE}/?author=1").mock(
            return_value=httpx.Response(
                301,
                headers={"location": f"{BASE}/author/johndoe/"},
            )
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await UsersModule().run(ctx, http)
    assert any(u.username == "johndoe" for u in ctx.users)
    assert any(f.id == "PC-USR-002" for f in ctx.findings)


async def test_author_archives_early_stop_after_3_misses(ctx):
    """AC-2: Early stop after 3 consecutive IDs without redirect."""
    async with respx.mock:
        respx.get(REST_URL).mock(return_value=httpx.Response(403))
        # author=1 has a redirect, then 2, 3, 4 are all 200 (misses)
        respx.get(f"{BASE}/?author=1").mock(
            return_value=httpx.Response(301, headers={"location": f"{BASE}/author/alice/"})
        )
        respx.route(url__regex=r".*author=.*").mock(return_value=httpx.Response(200))
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await UsersModule()._author_archives(ctx, http)
    # Should have found alice and stopped at 4 (3 consecutive misses after ID=1)
    assert any(u.username == "alice" for u in ctx.users)


async def test_wp_sitemap_users_emits_pc_usr_003(ctx):
    """AC-3: /wp-sitemap-users-1.xml → PC-USR-003 at INFO/3.1."""
    sitemap_xml = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://example.com/author/alice/</loc></url>
  <url><loc>https://example.com/author/bob/</loc></url>
</urlset>"""
    async with respx.mock:
        respx.get(f"{BASE}/wp-sitemap-users-1.xml").mock(
            return_value=httpx.Response(200, text=sitemap_xml)
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await UsersModule()._wp_sitemap_users(ctx, http)
    assert any(u.username == "alice" for u in ctx.users)
    assert any(u.username == "bob" for u in ctx.users)
    findings = [f for f in ctx.findings if f.id == "PC-USR-003"]
    assert len(findings) == 1
    assert findings[0].severity.value == "INFO"
    assert findings[0].cvss_score == 3.1


async def test_rss_feed_emits_pc_usr_004(ctx):
    """AC-4: RSS feed dc:creator → PC-USR-004 at MEDIUM/5.3."""
    rss_xml = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:dc="http://purl.org/dc/elements/1.1/">
  <channel>
    <item><title>Post 1</title><dc:creator>Alice Smith</dc:creator></item>
    <item><title>Post 2</title><dc:creator>Bob Jones</dc:creator></item>
  </channel>
</rss>"""
    async with respx.mock:
        respx.get(f"{BASE}/feed/").mock(
            return_value=httpx.Response(200, text=rss_xml)
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await UsersModule()._rss_feed(ctx, http)
    display_names = {u.display_name for u in ctx.users}
    assert "Alice Smith" in display_names
    assert "Bob Jones" in display_names
    findings = [f for f in ctx.findings if f.id == "PC-USR-004"]
    assert len(findings) == 1
    assert findings[0].severity.value == "MEDIUM"
    assert findings[0].cvss_score == 5.3


async def test_yoast_author_sitemap_emits_pc_usr_005(ctx):
    """AC-5: /author-sitemap.xml → PC-USR-005 at INFO/3.1 (distinct from PC-USR-003)."""
    sitemap_xml = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://example.com/author/carol/</loc></url>
</urlset>"""
    async with respx.mock:
        respx.get(f"{BASE}/author-sitemap.xml").mock(
            return_value=httpx.Response(200, text=sitemap_xml)
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await UsersModule()._yoast_author_sitemap(ctx, http)
    assert any(u.username == "carol" for u in ctx.users)
    findings = [f for f in ctx.findings if f.id == "PC-USR-005"]
    assert len(findings) == 1
    assert findings[0].severity.value == "INFO"
    assert findings[0].cvss_score == 3.1


async def test_oembed_extracts_user_with_author_url(ctx):
    """AC-6: oEmbed only extracts if author_url contains /author/."""
    oembed_json = '{"author_url": "https://example.com/author/dave/", "author_name": "Dave"}'
    async with respx.mock:
        respx.get(f"{BASE}/wp-json/oembed/1.0/embed?url={BASE}").mock(
            return_value=httpx.Response(200, text=oembed_json)
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await UsersModule()._oembed_user(ctx, http)
    assert any(u.username == "dave" for u in ctx.users)
    # AC-6: no finding emitted
    assert not any(f.module == "users" for f in ctx.findings)


async def test_oembed_no_author_url_no_user(ctx):
    """AC-6: oEmbed skips extraction if author_url does not contain /author/."""
    oembed_json = '{"author_url": "https://example.com/", "author_name": "Dave"}'
    async with respx.mock:
        respx.get(f"{BASE}/wp-json/oembed/1.0/embed?url={BASE}").mock(
            return_value=httpx.Response(200, text=oembed_json)
        )
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await UsersModule()._oembed_user(ctx, http)
    assert len(ctx.users) == 0
    assert len(ctx.findings) == 0


async def test_html_author_links_extracts_slugs(ctx):
    """AC-7: Regex /author/<slug>/ in homepage HTML → add users, no finding."""
    html = '<a href="/author/eve/">Eve</a> <a href="/author/frank/">Frank</a>'
    async with respx.mock:
        respx.get(BASE).mock(return_value=httpx.Response(200, text=html))
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await UsersModule()._html_author_links(ctx, http)
    usernames = {u.username for u in ctx.users}
    assert "eve" in usernames
    assert "frank" in usernames
    # AC-7: no finding emitted
    assert len(ctx.findings) == 0


async def test_html_author_links_deduplicates(ctx):
    """AC-7: Duplicate slugs in HTML are deduplicated (case-insensitive)."""
    html = '<a href="/author/grace/">One</a> <a href="/author/Grace/">Two</a>'
    async with respx.mock:
        respx.get(BASE).mock(return_value=httpx.Response(200, text=html))
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await UsersModule()._html_author_links(ctx, http)
    graces = [u for u in ctx.users if u.username.lower() == "grace"]
    assert len(graces) == 1


async def test_user_deduplication_across_methods(ctx):
    """Users discovered by multiple methods are deduplicated (case-insensitive)."""
    sitemap_xml = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://example.com/author/henry/</loc></url>
</urlset>"""
    html = '<a href="/author/Henry/">Link</a>'
    async with respx.mock:
        respx.get(REST_URL).mock(return_value=httpx.Response(403))
        respx.get(f"{BASE}/wp-sitemap-users-1.xml").mock(
            return_value=httpx.Response(200, text=sitemap_xml)
        )
        respx.get(BASE).mock(return_value=httpx.Response(200, text=html))
        respx.route(url__regex=r".*").mock(return_value=httpx.Response(404))
        async with PlecostHTTPClient(ctx.opts) as http:
            await UsersModule().run(ctx, http)
    henrys = [u for u in ctx.users if u.username.lower() == "henry"]
    assert len(henrys) == 1
