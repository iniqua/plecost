"""
Ensure all finding IDs follow the PC-XXX-NNN format and are unique.
This test must NEVER be broken — IDs are permanent and used in dashboards.
"""
import re

KNOWN_FINDING_IDS = [
    "PC-WP-001", "PC-WP-002",
    "PC-USR-001", "PC-USR-002", "PC-USR-003", "PC-USR-004", "PC-USR-005",
    "PC-BRU-001", "PC-BRU-002", "PC-BRU-003", "PC-BRU-004", "PC-BRU-007",
    "PC-AUTH-001", "PC-AUTH-002",
    "PC-XMLRPC-001", "PC-XMLRPC-002", "PC-XMLRPC-003",
    "PC-XMLRPC-004", "PC-XMLRPC-005", "PC-XMLRPC-006",
    "PC-REST-001", "PC-REST-002", "PC-REST-003",
    "PC-MCFG-001", "PC-MCFG-002", "PC-MCFG-003", "PC-MCFG-004",
    "PC-MCFG-005", "PC-MCFG-006", "PC-MCFG-007", "PC-MCFG-008",
    "PC-MCFG-009", "PC-MCFG-010", "PC-MCFG-011", "PC-MCFG-012",
    "PC-DIR-001", "PC-DIR-002", "PC-DIR-003", "PC-DIR-004",
    "PC-HDR-001", "PC-HDR-002", "PC-HDR-003", "PC-HDR-004",
    "PC-HDR-005", "PC-HDR-006", "PC-HDR-007", "PC-HDR-008",
    "PC-SSL-001", "PC-SSL-002", "PC-SSL-003",
    "PC-DBG-001", "PC-DBG-003",
    "PC-CNT-001", "PC-CNT-002", "PC-CNT-003",
    "PC-PRE-001", "PC-PRE-002",
    "PC-WAF-001",
    "PC-WC-000", "PC-WC-001", "PC-WC-002", "PC-WC-003",
    "PC-WC-004", "PC-WC-005", "PC-WC-006", "PC-WC-007",
    "PC-WC-008", "PC-WC-009", "PC-WC-010", "PC-WC-011",
    "PC-WC-012", "PC-WC-013",
    "PC-WC-020", "PC-WC-021",
    "PC-WPEC-000", "PC-WPEC-001", "PC-WPEC-002", "PC-WPEC-003",
    "PC-WPEC-004", "PC-WPEC-005", "PC-WPEC-006", "PC-WPEC-007",
    "PC-WPEC-008", "PC-WPEC-009", "PC-WPEC-010",
    "PC-WPEC-020", "PC-WPEC-021",
    "PC-MGC-000", "PC-MGC-001", "PC-MGC-002", "PC-MGC-003", "PC-MGC-004",
    "PC-WSH-001", "PC-WSH-100", "PC-WSH-150",
    "PC-WSH-200", "PC-WSH-250", "PC-WSH-300",
    # Wave 1: new findings added 2026-05-24
    "PC-MCFG-013", "PC-MCFG-014",
    "PC-MCFG-015", "PC-MCFG-016", "PC-MCFG-017", "PC-MCFG-018", "PC-MCFG-019",
    "PC-MCFG-020",
    "PC-DBG-002",
    "PC-XMLRPC-007",
    "PC-TTH-001", "PC-TTH-002", "PC-TTH-003",
    "PC-EMRG-001", "PC-EMRG-002", "PC-EMRG-003", "PC-EMRG-004", "PC-EMRG-005",
    "PC-BRUTE-001", "PC-BRUTE-002", "PC-BRUTE-003", "PC-BRUTE-004",
    "PC-WPH-001",
]

_ID_PATTERN = re.compile(r'^PC-[A-Z]+-\d{3}$')
_REM_PATTERN = re.compile(r'^REM-[A-Z]+-[A-Z0-9-]+$')


def test_all_finding_ids_follow_format():
    for fid in KNOWN_FINDING_IDS:
        assert _ID_PATTERN.match(fid), f"Invalid finding ID format: {fid}"


def test_no_duplicate_finding_ids():
    assert len(KNOWN_FINDING_IDS) == len(set(KNOWN_FINDING_IDS)), \
        "Duplicate finding IDs detected!"
