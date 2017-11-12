#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Plecost: Wordpress vulnerabilities finder
#
# @url: http://iniqua.com/labs/
# @url: https://github.com/iniqua/plecost
#
# @author:Francisco J. Gomez aka ffranz (http://iniqua.com/)
# @author:Daniel Garcia aka cr0hn (http://www.cr0hn.com/me/)
#
# Copyright (c) 2015, Iniqua Team
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
#
# 2. Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its
# contributors may be used to endorse or promote products derived from this
# software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
# IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
# OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#


"""
This file contains function to looking for WordPress plugins and versions
"""

import csv
import aiohttp
import asyncio
import datetime
import os.path as op

from functools import partial
from urllib.parse import urlparse

from .data import *  # noqa
from .db import DB
from .exceptions import *  # noqa
from .plugins_utils import plugins_testing
from .helpers import is_remote_a_wordpress, get_wordpress_version
from .utils import colorize, generate_error_page, download, get_data_folder


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
    start_time = datetime.datetime.now()
    no_check_wordpress = args.no_check_wordpress
    no_check_plugins = args.no_check_plugins
    no_check_wordpress_version = args.no_check_wordpress_version
    force_scan = args.force_scan
    ignore_403 = args.ignore_403
    hostname = args.hostname

    # Jackass mode is set?
    if args.jackass is True:
        concurrency = 9999

    # Non-blocking config
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    conn = aiohttp.TCPConnector(verify_ssl=False)
    session = aiohttp.ClientSession(loop=loop, connector=conn)
    _download = partial(download,
                        session=session,
                        max_redirect=0,
                        loop=loop,
                        custom_hostname=hostname)

    # Get CVE database
    db = DB(path=op.join(get_data_folder(), "cve.db"))

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

            _is_wp = loop.run_until_complete(is_remote_a_wordpress(url,
                                                                   error_page,
                                                                   _download))

            if not _is_wp:
                if force_scan is False:
                    raise PlecostNotWordPressFound("No WordPress installations found in '%s'." % host)
                else:
                    log(colorize("\n   No Wordpress installation found!\n", "yellow"))
            else:
                log("\n   %s" % colorize(" ok!\n"))

    # --------------------------------------------------------------------------
    # Check WordPress version
    # --------------------------------------------------------------------------
    if no_check_wordpress_version is False:
            log("[*] Getting WordPress version... ")

            wordpress_version = loop.run_until_complete(get_wordpress_version(url, _download, db))
            # wordpress_version.
            if wordpress_version:
                log("%s (latest: %s)" %
                    (
                        colorize("%s" % wordpress_version.current_version,
                                 "red" if wordpress_version.is_outdated is True else "blue"),
                        colorize("%s" % wordpress_version.latest_version)
                    ), 0)

                # --------------------------------------------------------------------------
                # Looking for CVEs for installed Wordpress version
                # --------------------------------------------------------------------------
                if wordpress_version.vulnerabilities:
                    log("\n    |_CVE list:\n")
                    for cve in wordpress_version.vulnerabilities:
                        log("    |__%(cve)s: (http://cve.mitre.org/cgi-bin/cvename.cgi?name=%(cve)s)\n" %
                            {"cve": colorize(cve, "red")})
                    log("\n")
            else:
                    log(colorize("Unknown!\n", "red"))

            log("\n")
    else:
        wordpress_version = PlecostWordPressInfo(last_version="",
                                                 current_version="",
                                                 vulnerabilities=[])

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
                                                               session,
                                                               error_page,
                                                               log,
                                                               cve_info,
                                                               db,
                                                               concurrency,
                                                               ignore_403,
                                                               loop))
    log("\n[*] Done! \n")

    # Set finish time
    end_time = datetime.datetime.now()

    # --------------------------------------------------------------------------
    # Clean up
    # --------------------------------------------------------------------------
    session.close()
    conn.close()

    # --------------------------------------------------------------------------
    # Make results
    # --------------------------------------------------------------------------
    return PlecostResults(target=args.target,
                          start_time=start_time,
                          end_time=end_time,
                          wordpress_info=wordpress_version,
                          plugins=plugins_info)


__all__ = ["find_versions", "_is_remote_a_wordpress"]
