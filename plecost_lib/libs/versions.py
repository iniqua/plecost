#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Plecost: Wordpress finger printer tool.
#
# @url: http://iniqua.com/labs/
# @url: https://github.com/iniqua/plecost
#
# @author:Francisco J. Gomez aka ffranz (http://iniqua.com/)
# @author:Daniel Garcia aka cr0hn (http://www.cr0hn.com/me/)
#
# Code is licensed under -- GPLv2, http://www.gnu.org/licenses/gpl.html --
#


"""
This file contains function to looking for WordPress plugins and versions
"""

import csv
import aiohttp
import asyncio

from datetime import datetime
from functools import partial
from urllib.parse import urlparse
from os.path import join

from .db import DB
from .data import *  # noqa
from .exceptions import *  # noqa
from .plugins_utils import plugins_testing
from .utils import colorize, generate_error_page, download, get_data_folder
from .wordpress_core import is_remote_a_wordpress, get_wordpress_version, get_wordpress_vulnerabilities


# ----------------------------------------------------------------------
# Main code of functions
# ----------------------------------------------------------------------
def find_versions(args):
    """
    Main function to run libs as version finder.

    :param args: PlecostOptions object
    :type args: `PlecostOptions`

    :return: PlecostResults object.
    :rtype: `PlecostResults`

    :raises: PlecostTargetNotAvailable, PlecostNotWordPressFound
    """
    # --------------------------------------------------------------------------
    # Common vars
    # --------------------------------------------------------------------------
    url = args.target
    parsed_url = urlparse(args.target)
    host = parsed_url.hostname
    concurrency = args.concurrency
    log = args.log_function
    proxy = args.proxy
    is_color = args.colorize
    start_time = datetime.now()
    no_check_wordpress = args.no_check_wordpress
    no_check_plugins = args.no_check_plugins
    no_check_wordpress_version = args.no_check_wordpress_version

    # Non-blocking config
    loop = asyncio.get_event_loop()
    con = aiohttp.TCPConnector(conn_timeout=10, share_cookies=True, loop=loop)
    _download = partial(download, max_redirect=0, connector=con, loop=loop)

    # Get CVE database
    db = DB(path=join(get_data_folder(), "cve.db"))

    # --------------------------------------------------------------------------
    # Test availability of target
    # --------------------------------------------------------------------------
    log("[*] Testing target connection...")
    headers, status, content = loop.run_until_complete(_download(url, method="get", get_content=False))

    # Detect redirect
    if status in (300, 301, 302, 303, 307):
        url = headers.get("location", None)

        if url is not None:
            log("\n[%s] Redirection detected to '%s'. Using it now. " % (colorize("ii", "yellow"), url),
                log_level=1)
        else:
            raise PlecostTargetNotAvailable("Redirection detected, but can't determinate the new location")
    log(colorize(" ok!\n"))

    # --------------------------------------------------------------------------
    # Check if remote host is a WordPress
    # --------------------------------------------------------------------------
    if no_check_wordpress is False:
            log("[*] Looking for WordPress installation...\n")
            # Error page content.
            headers, status, error_page = loop.run_until_complete(_download(generate_error_page(url)))

            _is_wp = loop.run_until_complete(is_remote_a_wordpress(url, error_page, _download))

            if not _is_wp:
                raise PlecostNotWordPressFound("No WordPress installations found in '%s'." % host)

            log("\n   %s" % colorize(" ok!\n"))

    # --------------------------------------------------------------------------
    # Check WordPress version
    # --------------------------------------------------------------------------
    if no_check_wordpress_version is False:
            log("[*] Getting WordPress version... ")

            wordpress_version = loop.run_until_complete(get_wordpress_version(url, _download))
            # wordpress_version.
            if wordpress_version:
                log("%s (latest: %s)" %
                    (
                        colorize("%s" % wordpress_version.current_version, "red"),
                        colorize("%s" % wordpress_version.latest_version)
                    ), 0)
            else:
                    log(colorize("Unknown!\n", "red"))

            # --------------------------------------------------------------------------
            # Looking for CVEs for installed Wordpress version
            # --------------------------------------------------------------------------
            log(get_wordpress_vulnerabilities(wordpress_version, db))

            log("\n")
    # --------------------------------------------------------------------------
    # Check the plugins
    # --------------------------------------------------------------------------
    # Read plugins file and remove \n and \r
    plugins_info = []

    if no_check_plugins is False:
        plugins = []
        plugins_append = plugins.append

        with open(args.wordlist, "rU") as f:
            for plugin in f:
                plugins_append(plugin.replace("\n", "").replace("\r", ""))

        # Prepare csv file
        cve_info = csv.reader(plugins)
        error_page = ""
        # Find plugins
        log("[*] Looking for plugins (wordlist: %s) ... " % args.wordlist[args.wordlist.rfind("/") + 1:], 0)

        plugins_info = loop.run_until_complete(plugins_testing(url,
                                                               error_page,
                                                               log,
                                                               cve_info,
                                                               db,
                                                               concurrency,
                                                               loop,
                                                               con=con))
    log("\n[*] Done! \n")

    # Set finish time
    end_time = datetime.now()

    # --------------------------------------------------------------------------
    # Clean up
    # --------------------------------------------------------------------------
    con.close()

    # --------------------------------------------------------------------------
    # Make results
    # --------------------------------------------------------------------------
    _d = PlecostWordPressInfo(current_version="4.1.1",
                              last_version="4.1.1")

    return PlecostResults(target=args.target,
                          start_time=start_time,
                          end_time=end_time,
                          # wordpress_info=wordpress_version,
                          wordpress_info=_d,
                          plugins=plugins_info)


__all__ = ["find_versions", "_is_remote_a_wordpress"]