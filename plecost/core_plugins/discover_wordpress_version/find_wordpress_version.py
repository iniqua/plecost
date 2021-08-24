import re
import argparse
import urllib.parse as op

from typing import Tuple

from plecost.network import HTTP
from plecost.models import WordpressVersion

REGEX_LATEST_WORDPRESS_VERSION = re.compile(r"(WordPress&nbsp;)([0-9.]*)")
REGEX_WORDPRESS_VERSION_README = re.compile(r"""(<br[\s]*/>[\s]*[Vv]ersion[\s]*)([\d]\.[\d]\.*[\d]*)""")
REGEX_WORDPRESS_VERSION_GENERATOR = re.compile(r'''(<meta name=\"generator\" content=\"WordPress[\s]+)([0-9.]+)''')
REGEX_FIND_VER = re.compile(r'''(\?ver\=[\s]*)([\.\d\w]+)([\s\"\']+)''')
REGEX_FIND_CSS_SCRIPT_LINKS = re.compile(r'''((script|link).*(src|href)=)(.*)(>)''')

class PlecostWordpressVersion:
    slug = "core-wordpress-version-finder"
    name = "Wordpress version finder"
    description = "Discover wordpress version"
    author = "Iniqua Team"

    def __init__(self):
        self.running_config: dict = {}

    def init(self, running_config: dict):
        self.running_config = running_config

    def cli_run(self, parser: argparse.ArgumentParser) -> argparse._ArgumentGroup:
        gr = parser.add_argument_group("wordpress version finder")
        gr.add_argument('-nv', '--no-wordpress-version',
                        dest="NO_CHECK_WORDPRESS_VERSION",
                        action="store_true",
                        default=False,
                        help="do not check Wordpress version")

    async def on_finding_wordpress(self, on_start_results: dict):

        installed_version = await self._get_wordpress_version_(
            self.running_config["target"]
        )

        latest_version, wordpress_versions = await self._get_latest_wordpress_version_()

        status = "unknown"
        if installed_version:
            if v := wordpress_versions.get(installed_version):
                status = v

        return WordpressVersion(
            status=status,
            installed_version=installed_version,
            latest_version=latest_version
        )

    async def _get_wordpress_version_(self, url: str):
        """
        This functions checks remote WordPress version.

        :param url: site to looking for WordPress version
        :type url: basestring

        :param downloader: download function_plugin_foundon. This function must accept only one parameter: the URL
        :type downloader: function

        :param db: cve database instance
        :type db: DB

        :return: PlecostWordPressInfo instance.
        :rtype: `PlecostWordPressInfo`
        """

        latest_version = None
        total_checking_methods = 4

        for method in range(1, total_checking_methods):
            coro = getattr(self, f"_get_wordpress_version_method_{method}")

            if ret := await coro(url):
                latest_version = ret
                break

        else:
            latest_version = "unknown"

        return latest_version

    async def _get_latest_wordpress_version_(self) -> Tuple[str, dict]:
        # --------------------------------------------------------------------------
        # Get last Wordpress version
        # --------------------------------------------------------------------------
        latest_version = None
        # URL to get last version of WordPress available
        try:
            _, wordpress_versions = await HTTP.get_json("http://api.wordpress.org/core/stable-check/1.0/")

            for version, status in wordpress_versions.items():
                if status == "latest":
                    latest_version = version

        except Exception:
            pass

        if not latest_version:
            latest_version = "unknown"

        return latest_version, wordpress_versions

    async def _get_wordpress_version_method_1(self, url: str):
        """
        Method 1: Looking for in readme.txt
        """
        status, html_content = await HTTP.get(
            op.urljoin(url, "/readme.html")
        )

        if status != 200:
            return

        curr_ver = None

        if ver := REGEX_WORDPRESS_VERSION_README.search(html_content):
            if len(ver.groups()) != 2:
                curr_ver = None
            else:
                curr_ver = ver.group(2)

        return curr_ver

    async def _get_wordpress_version_method_2(self, url: str):
        """
        Method 2: Looking for meta tag
        """
        status, html_content = await HTTP.get(url)

        if status != 200:
            return

        # Try to find the info
        cur_ver = None

        if v := REGEX_WORDPRESS_VERSION_GENERATOR.search(html_content):
            if len(v.groups()) == 2:
                cur_ver = v.group(2)

        return cur_ver

    async def _get_wordpress_version_method_3(self, url: str):
        """
        Method 2: Looking for meta tag
        """
        url_version = {
            # Generic
            "wp-login.php": r"(;ver=)([0-9\.]+)([\-a-z]*)",

            # For WordPress 3.8
            "wp-admin/css/wp-admin-rtl.css": r"(Version[\s]+)([0-9\.]+)",
            "wp-admin/css/wp-admin.css": r"(Version[\s]+)([0-9\.]+)"
        }

        for path, regex in url_version.items():

            status, html_content = await HTTP.get(op.urljoin(url, path))

            if status != 200:
                return

            if v := re.search(regex, html_content):
                return v.group(2)
