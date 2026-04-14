from __future__ import annotations
from datetime import date

# ── Fast webshell filenames (~21 names): highest-frequency families seen in real WP compromises
# Sources: Sucuri SiteCheck, Wordfence Threat Intelligence, NinjaFirewall incident reports
WEBSHELL_FILENAMES_FAST: list[str] = [
    # Classic families — found in >80% of WordPress compromises
    "c99.php", "c99shell.php", "r57.php", "wso.php", "alfa.php",
    # Generic shells — extremely common in automated mass-exploitation
    "shell.php", "cmd.php", "webshell.php", "backdoor.php",
    # IndoXploit — dominant in SEA/South Asian attacks 2021-2025
    "indoxploit.php",
    # WP-impersonating names — blend into WP file tree
    "wp.php", "wp-tmp.php", "wp-feed.php", "wp-cache.php",
    # Camouflage names — generic enough to avoid casual inspection
    "cache.php", "config.php", "update.php",
    # Upload-themed — almost always dropped via file-upload exploits
    "upload.php", "image.php",
    # Short/random — product of automated dropper scripts
    "1.php", "x.php",
]

# ── Common webshell filenames (families: c99, r57, WSO, b374k, P.A.S., Alfa, Godzilla)
WEBSHELL_FILENAMES_CORE: list[str] = [
    # Direct names
    "c99.php", "c99shell.php", "r57.php", "r57shell.php",
    "wso.php", "b374k.php", "alfa.php", "shell.php", "cmd.php",
    "webshell.php", "backdoor.php", "indoxploit.php", "pas.php",
    # Camouflage — imitating WP/generic files
    "cache.php", "settings.php", "config.php", "update.php",
    "install.php", "error.php", "maintenance.php", "css.php",
    "style.php", "functions.php", "license.php", "readme.php",
    # Upload-themed names
    "image.php", "img.php", "upload.php", "file.php", "thumb.php",
    # Short/random names common in automated attacks
    "1.php", "2.php", "x.php", "a.php", "z.php",
    # WordPress-impersonating names
    "wp.php", "wp-tmp.php", "wp-feed.php", "wp-core.php",
    "wp-cache.php", "wp-debug.php", "wp-backup.php",
]

WEBSHELL_FILENAMES_EXTENDED: list[str] = WEBSHELL_FILENAMES_CORE + [
    "tool.php", "tools.php", "manager.php", "admin.php", "panel.php",
    "console.php", "terminal.php", "exec.php", "run.php", "system.php",
    "sh.php", "php.php", "info.php", "test.php", "tmp.php",
    "temp.php", "old.php", "new.php", "bk.php", "log.php",
    "cgi.php", "pass.php", "db.php", "sql.php", "wp-load.php",
    "wp-user.php", "wp-post.php", "wp-admin.php", "wp-conf.php",
    "index2.php", "index3.php", "wp2.php",
]

_WEBSHELL_DIRS_CORE: list[str] = [
    "/wp-content/uploads/",
    "/wp-content/mu-plugins/",
    "/wp-includes/css/",
    "/wp-includes/images/",
    "/wp-admin/css/",
    "/wp-admin/includes/",
    "/",
]

# All combinations of dirs × filenames
WEBSHELL_PATHS_FAST: list[str] = [
    d + name
    for d in _WEBSHELL_DIRS_CORE
    for name in WEBSHELL_FILENAMES_FAST
]

WEBSHELL_PATHS_CORE: list[str] = [
    d + name
    for d in _WEBSHELL_DIRS_CORE
    for name in WEBSHELL_FILENAMES_CORE
]

WEBSHELL_PATHS_EXTENDED: list[str] = [
    d + name
    for d in _WEBSHELL_DIRS_CORE
    for name in WEBSHELL_FILENAMES_EXTENDED
] + [
    # Specific known paths seen in real attacks
    "/wp-content/plugins/blnmrpb/index.php",
    "/wp-content/plugins/akismet/index2.php",
    "/wp-content/uploads/wflogs/rules.php",
    "/wp-content/uploads/gravity_forms/shell.php",
    "/wp-includes/pomo/index.php",
]

# ── Filenames probed in wp-content/uploads/ (with year/month paths)
UPLOADS_PHP_NAMES: list[str] = [
    "c99.php", "r57.php", "wso.php", "shell.php", "cmd.php",
    "backdoor.php", "upload.php", "file.php", "image.php",
    "img.php", "cache.php", "wp.php", "1.php", "x.php",
    "alfa.php", "webshell.php", "b374k.php", "config.php",
    "update.php", "thumb.php", "functions.php",
]

def _uploads_paths(all_years: bool = True) -> list[str]:
    """Generate year/month upload paths.

    Fast mode (all_years=False): root uploads + current year only (~273 paths).
    Deep mode (all_years=True): root uploads + every year from 2020 (~1785 paths).
    """
    paths: list[str] = []
    current_year = date.today().year
    years = range(2020, current_year + 1) if all_years else range(current_year, current_year + 1)
    for year in years:
        for month in range(1, 13):
            prefix = f"/wp-content/uploads/{year}/{month:02d}/"
            for name in UPLOADS_PHP_NAMES:
                paths.append(prefix + name)
    for name in UPLOADS_PHP_NAMES:
        paths.append("/wp-content/uploads/" + name)
    return paths

UPLOADS_PROBE_PATHS_FAST: list[str] = _uploads_paths(all_years=False)
UPLOADS_PROBE_PATHS: list[str] = _uploads_paths(all_years=True)

# ── Filenames probed in mu-plugins (seen in real attacks 2024-2025, Sucuri research)
MU_PLUGINS_NAMES: list[str] = [
    "index.php", "redirect.php", "custom-js-loader.php",
    "loader.php", "wp-plugin.php", "cache.php", "update.php",
    "maintenance.php", "autoload.php", "init.php", "bootstrap.php",
    "hook.php", "filter.php", "security.php", "admin.php",
    "db.php", "object-cache.php", "advanced-cache.php",
    "plugin.php", "load.php", "wp-cache.php", "wp.php",
    "functions.php", "config.php", "settings.php",
]

# ── WordPress core files to verify via checksums API
WP_CORE_FILES_TO_CHECK: list[str] = [
    "wp-login.php",
    "wp-includes/functions.php",
    "wp-includes/class-wp-hook.php",
    "wp-includes/plugin.php",
    "wp-includes/load.php",
    "wp-admin/includes/plugin.php",
    "wp-settings.php",
    "index.php",
    "wp-blog-header.php",
    "xmlrpc.php",
    "wp-cron.php",
    "wp-includes/ms-functions.php",
    "wp-includes/class-wp-error.php",
    "wp-includes/capabilities.php",
    "wp-includes/user.php",
    "wp-admin/admin.php",
    "wp-admin/admin-ajax.php",
    "wp-admin/admin-post.php",
    "wp-admin/includes/misc.php",
    "wp-admin/includes/file.php",
]
