from __future__ import annotations
import asyncio
from plecost.engine.context import ScanContext
from plecost.engine.http_client import PlecostHTTPClient
from plecost.modules.base import ScanModule
from plecost.modules.webshells.base import BaseDetector
from plecost.modules.webshells.detectors.known_paths import KnownPathsDetector
from plecost.modules.webshells.detectors.uploads_php import UploadsPhpDetector
from plecost.modules.webshells.detectors.mu_plugins import MuPluginsDetector
from plecost.modules.webshells.detectors.response_fp import ResponseFingerprintDetector
from plecost.modules.webshells.detectors.checksums import ChecksumsDetector
from plecost.modules.webshells.detectors.fake_plugins import FakePluginRestDetector


class WebshellsModule(ScanModule):
    """
    Remote webshell detection for WordPress.

    Black-box detectors (no credentials required):
      - known_paths: probes ~100-300 known webshell filenames in WP directories
      - uploads_php: detects PHP execution in wp-content/uploads
      - mu_plugins: detects PHP files in wp-content/mu-plugins
      - response_fp: fingerprints response bodies against known webshell families

    Grey-box detectors (requires --user / --password):
      - checksums: verifies WP core file integrity via api.wordpress.org
      - fake_plugins: detects unknown plugins via WP REST API

    Module options (--module-option webshells:KEY=VALUE):
      - wordlist=core (default) | extended   — wordlist size for path probing
      - detectors=name1,name2               — run only specified detectors
    """

    name = "webshells"
    depends_on = ["fingerprint", "plugins"]

    _all_detectors: list[BaseDetector] = [
        KnownPathsDetector(),
        UploadsPhpDetector(),
        MuPluginsDetector(),
        ResponseFingerprintDetector(),
        ChecksumsDetector(),
        FakePluginRestDetector(),
    ]

    async def run(self, ctx: ScanContext, http: PlecostHTTPClient) -> None:
        options = ctx.opts.module_options.get("webshells", {})

        # Filter by detectors option if specified
        enabled_names: set[str] | None = None
        if "detectors" in options:
            enabled_names = {n.strip() for n in options["detectors"].split(",")}

        active: list[BaseDetector] = []
        for detector in self._all_detectors:
            if enabled_names is not None and detector.name not in enabled_names:
                continue
            if detector.requires_auth and not ctx.opts.credentials:
                continue
            active.append(detector)

        results = await asyncio.gather(
            *[d.detect(ctx, http) for d in active],
            return_exceptions=True,
        )
        for result in results:
            if isinstance(result, list):
                for finding in result:
                    ctx.add_finding(finding)
            # exceptions are silently ignored (project convention)
