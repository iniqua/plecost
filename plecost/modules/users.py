from __future__ import annotations
import json
import re
import asyncio
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import Finding, Severity, User
from plecost.modules.base import ScanModule


class UsersModule(ScanModule):
    name = "users"
    depends_on = ["fingerprint"]
    _MAX_AUTHOR_ID = 10

    async def run(self, ctx: ScanContext, http: PlecostHTTPClient) -> None:
        if not ctx.is_wordpress and not ctx.opts.force:
            return
        await asyncio.gather(
            self._rest_api(ctx, http),
            self._author_archives(ctx, http),
        )

    async def _rest_api(self, ctx: ScanContext, http: PlecostHTTPClient) -> None:
        try:
            r = await http.get(f"{ctx.url}/wp-json/wp/v2/users")
            if r.status_code != 200:
                return
            try:
                users_data = json.loads(r.text)
            except json.JSONDecodeError:
                # WordPress may return HTML when REST API is restricted
                return
            if not isinstance(users_data, list) or not users_data:
                return
            for u in users_data:
                ctx.add_user(User(
                    id=u.get("id"), username=u.get("slug", ""),
                    display_name=u.get("name"), source="rest_api"
                ))
            users_formatted = "\n".join(
                f"  • [id:{u.get('id')}] {u.get('name', '?')} (@{u.get('slug', '?')}) — {u.get('link', '')}"
                for u in users_data
            )
            ctx.add_finding(Finding(
                id="PC-USR-001", remediation_id="REM-USR-001",
                title="User enumeration via REST API",
                severity=Severity.MEDIUM,
                description=f"REST API exposes {len(users_data)} user(s): {[u.get('slug') for u in users_data]}",
                evidence={"url": f"{ctx.url}/wp-json/wp/v2/users", "users": users_formatted},
                remediation="Restrict REST API user endpoint. Add to functions.php: add_filter('rest_endpoints', function($e){ unset($e['/wp/v2/users']); return $e; });",
                references=["https://www.wordfence.com/learn/wordpress-rest-api/"],
                cvss_score=5.3, module=self.name
            ))
        except Exception:
            pass

    async def _author_archives(self, ctx: ScanContext, http: PlecostHTTPClient) -> None:
        found_users: list[str] = []
        for i in range(1, self._MAX_AUTHOR_ID + 1):
            try:
                r = await http.get(f"{ctx.url}/?author={i}", follow_redirects=False)
                if r.status_code in (301, 302):
                    location = r.headers.get("location", "")
                    if m := re.search(r'/author/([^/]+)/', location):
                        username = m.group(1)
                        found_users.append(username)
                        if not any(u.username == username for u in ctx.users):
                            ctx.add_user(User(id=i, username=username, display_name=None, source="author_archive"))
            except Exception:
                break
        if found_users:
            ctx.add_finding(Finding(
                id="PC-USR-002", remediation_id="REM-USR-002",
                title="User enumeration via author archives",
                severity=Severity.MEDIUM,
                description=f"Author archives expose usernames: {found_users}",
                evidence={"users": found_users},
                remediation="Redirect /?author=N requests to homepage. Add rewrite rules in .htaccess or nginx config.",
                references=[], cvss_score=5.3, module=self.name
            ))
