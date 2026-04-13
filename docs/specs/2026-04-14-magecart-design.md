# Magecart / Card Skimming Detection Module

**Date:** 2026-04-14  
**Status:** Approved  
**Scope:** Single module `magecart` added to plecost

---

## Problem

WooCommerce and WP eCommerce sites are primary targets of Magecart attacks — supply-chain
injections that load card-skimming JavaScript from attacker-controlled domains on checkout pages.
No existing plecost module detects this. The current `content_analysis` module (PC-CNT-001)
only performs a superficial keyword match on `<script src>` attributes and does not consult
any reputation data.

---

## Approach

Domain blocklist lookup against a curated list stored in the plecost DB, updated automatically
via the existing `plecost update-db` patch mechanism. Detection is **passive only** (GET requests),
**blocklist-only** (no false positives from heuristics), and **eCommerce-gated** (only runs when
WooCommerce or WP eCommerce is detected).

---

## Architecture

### Module

```
plecost/modules/magecart.py
  MagecartModule
    name = "magecart"
    depends_on = ["fingerprint", "woocommerce", "wp_ecommerce"]
```

**Run flow:**

1. `_should_run(ctx)` — returns `True` only if `ctx.woocommerce` or `ctx.wp_ecommerce` is set
2. `_get_checkout_urls(ctx)` — builds URL list based on detected plugins:
   - WooCommerce → `/checkout`, `/cart`
   - WP eCommerce → `/?pagename=checkout`, `/?pagename=cart`
   - Both → union, deduplicated
3. `asyncio.gather(*[_scan_page(..., url) for url in urls])` — parallel GET requests
4. `_emit_summary(ctx)` — always emits PC-MGC-000 when module ran

**`_scan_page(ctx, http, store, url)`:**

- GET `url` — if non-200, skip silently
- Extract all `<script src="https://EXTERNAL_DOMAIN/...">` where domain ≠ ctx.url base domain
- `store.get_magecart_domains(extracted_domains)` — DB lookup
- For each match: emit PC-MGC-001/002/003 (checkout page) or PC-MGC-004 (non-checkout)

### New dataclass in `models.py`

```python
@dataclass
class MagecartInfo:
    detected: bool
    pages_scanned: list[str]
    scripts_analyzed: int
    malicious_domains: list[str]
```

Added to `ScanResult` as `magecart: MagecartInfo | None = None`.  
Added to `ScanContext` as `self.magecart: MagecartInfo | None = None`.

### JSON output section

```json
{
  "magecart": {
    "detected": true,
    "pages_scanned": ["/checkout", "/cart"],
    "scripts_analyzed": 12,
    "malicious_domains": ["analytics-cdn.ru"]
  }
}
```

---

## Database

### New table: `MagecartDomain`

```python
class MagecartDomain(Base):
    __tablename__ = "magecart_domains"
    domain: Mapped[str]       # Primary key — e.g. "analytics-cdn.ru"
    category: Mapped[str]     # "magecart" | "dropper" | "exfiltrator"
    source: Mapped[str]       # Origin of the IOC (e.g. "groups123", "feodotracker")
    added_date: Mapped[str]   # ISO date string
    is_active: Mapped[bool]   # False = soft-deleted
```

### New query in `CVEStore`

```python
async def get_magecart_domains(self, domains: list[str]) -> list[MagecartDomain]:
    # SELECT * FROM magecart_domains
    # WHERE domain IN (:domains) AND is_active = true
```

### `update-db` integration

Same release tag `db-patches` gains a new file: `magecart-domains.json`

Format (reuses existing patch system upsert/soft-delete schema):
```json
{
  "upserts": [
    {"domain": "evil-cdn.ru", "category": "magecart", "source": "groups123",
     "added_date": "2026-04-14", "is_active": true}
  ],
  "deletes": []
}
```

`downloader.py` / `updater.py` downloads `magecart-domains.json` in the same pass as `full.json`.
No new CLI commands required.

---

## Finding IDs

| ID | Severity | CVSS | Description |
|----|----------|------|-------------|
| PC-MGC-000 | INFO | — | Magecart scan summary |
| PC-MGC-001 | CRITICAL | 9.8 | Known Magecart domain script on checkout page |
| PC-MGC-002 | CRITICAL | 9.8 | Known dropper domain script on checkout page |
| PC-MGC-003 | HIGH | 8.1 | Known exfiltrator domain script on checkout page |
| PC-MGC-004 | MEDIUM | 5.3 | Known Magecart domain script on non-checkout page |

Severity by `category` × page type:
- `magecart` on checkout → PC-MGC-001 CRITICAL
- `dropper` on checkout → PC-MGC-002 CRITICAL
- `exfiltrator` on checkout → PC-MGC-003 HIGH
- Any category on homepage/non-checkout → PC-MGC-004 MEDIUM

---

## Files to Create/Modify

| File | Action | Reason |
|------|--------|--------|
| `plecost/models.py` | Modify | Add `MagecartInfo`, `magecart` field in `ScanResult` |
| `plecost/engine/context.py` | Modify | Add `self.magecart: MagecartInfo \| None = None` |
| `plecost/database/models.py` (or `store.py`) | Modify | Add `MagecartDomain` ORM model |
| `plecost/database/store.py` | Modify | Add `get_magecart_domains()` query |
| `plecost/database/downloader.py` | Modify | Download `magecart-domains.json` alongside `full.json` |
| `plecost/database/patch_applier.py` | Modify | Apply upserts/soft-deletes for `magecart_domains` table |
| `plecost/modules/magecart.py` | Create | The full module |
| `plecost/scanner.py` | Modify | Register `MagecartModule`, add `magecart=ctx.magecart` to `ScanResult` |
| `plecost/cli.py` | Modify | 5 PC-MGC-* IDs in `_FINDINGS_REGISTRY`, add `"magecart"` to `_ALL_MODULE_NAMES` |
| `tests/unit/test_module_magecart.py` | Create | ~20 unit tests |
| `tests/unit/test_database_magecart.py` | Create | DB query tests |
| `tests/contract/test_finding_ids.py` | Modify | Add 5 PC-MGC-* IDs |
| `CHANGELOG.md` | Modify | Document changes |

---

## Tests

### Unit tests (`test_module_magecart.py`, ~17 tests)

- `test_skips_if_no_ecommerce_detected` — no ctx.woocommerce, no ctx.wp_ecommerce → no findings
- `test_detects_magecart_script_on_checkout` → PC-MGC-001
- `test_detects_dropper_on_checkout` → PC-MGC-002
- `test_detects_exfiltrator_on_checkout` → PC-MGC-003
- `test_lower_severity_outside_checkout` → PC-MGC-004
- `test_clean_site_no_findings` — scripts from unlisted domains → no findings
- `test_checkout_urls_woocommerce` — /checkout, /cart in URL list
- `test_checkout_urls_wp_ecommerce` — /?pagename=checkout in URL list
- `test_checkout_urls_both_plugins` — union, no duplicates
- `test_summary_always_emitted` → PC-MGC-000
- `test_ctx_magecart_populated` — ctx.magecart.malicious_domains correct
- `test_page_404_skipped_gracefully` — no crash on 404
- `test_inline_scripts_ignored` — no src attribute → not analyzed
- `test_same_domain_script_ignored` — relative/same-domain script → ignored
- `test_multiple_malicious_scripts` — 2 matches → 2 findings
- `test_db_store_called_with_correct_domains` — verifies query input

### DB tests (`test_database_magecart.py`, ~3 tests)

- `test_get_magecart_domains_returns_matches`
- `test_get_magecart_domains_empty_db`
- `test_get_magecart_domains_inactive_excluded`

### Contract tests

Add PC-MGC-000 through PC-MGC-004 to `KNOWN_FINDING_IDS`.

---

## Key Constraints

- **Async-safe**: all HTTP via `await http.get(...)`, parallel pages via `asyncio.gather()`
- **Passive only**: no POST, no semi-active mode needed
- **No module_options**: no configuration needed — always blocklist-only
- **Graceful degradation**: if `magecart_domains` table is empty (DB not updated yet), module runs but emits only PC-MGC-000 with 0 malicious domains
- **DB migration**: `MagecartDomain` table created via SQLAlchemy `create_all` on first run
