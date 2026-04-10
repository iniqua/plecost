from __future__ import annotations
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.models import Finding, Severity
from plecost.modules.base import ScanModule


class AuthModule(ScanModule):
    name = "auth"
    depends_on = ["fingerprint"]

    async def run(self, ctx: ScanContext, http: PlecostHTTPClient) -> None:
        if not ctx.is_wordpress or not ctx.opts.credentials:
            return
        username, password = ctx.opts.credentials
        await self._login(ctx, http, username, password)
        await self._check_open_registration(ctx, http)

    async def _login(self, ctx: ScanContext, http: PlecostHTTPClient, user: str, pwd: str) -> bool:
        try:
            login_url = f"{ctx.url}/wp-login.php"
            data = {
                "log": user, "pwd": pwd,
                "wp-submit": "Log In", "redirect_to": "/wp-admin/",
                "testcookie": "1",
            }
            r = await http.post(login_url, data=data)
            if r.status_code in (200, 302) and "wp-admin" in r.text + r.headers.get("location", ""):
                ctx.add_finding(Finding(
                    id="PC-AUTH-001", remediation_id="REM-AUTH-001",
                    title="Successful authentication with provided credentials",
                    severity=Severity.INFO,
                    description=f"Successfully authenticated as '{user}'.",
                    evidence={"username": user, "login_url": login_url},
                    remediation="Change default credentials immediately. Use a strong password.",
                    references=[], cvss_score=None, module=self.name
                ))
                return True
        except Exception:
            pass
        return False

    async def _check_open_registration(self, ctx: ScanContext, http: PlecostHTTPClient) -> None:
        try:
            r = await http.get(f"{ctx.url}/wp-login.php?action=register")
            if r.status_code == 200 and "user_login" in r.text:
                ctx.add_finding(Finding(
                    id="PC-AUTH-002", remediation_id="REM-AUTH-002",
                    title="Open user registration enabled",
                    severity=Severity.MEDIUM,
                    description="Anyone can register an account on this WordPress site.",
                    evidence={"url": f"{ctx.url}/wp-login.php?action=register"},
                    remediation="Disable in Settings > General > Membership > Anyone can register.",
                    references=[], cvss_score=5.3, module=self.name
                ))
        except Exception:
            pass
