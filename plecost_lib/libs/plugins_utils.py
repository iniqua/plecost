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

import re
import asyncio

from os.path import join
from functools import partial
from urllib.parse import urljoin

from .data import PlecostPluginInfo
from .utils import colorize, get_diff_ratio, ConcurrentDownloader, get_data_folder

exp = re.compile(r"([Ss]table tag:[\s]*)([\svV]*[0-9\.]+|trunk)")
exp_change_log = re.compile(r"([\=\-]\s*)([\d]+\.[\d]+\.*[\d]*\.*[\d]*\.*[\d]*\.*[\d]*)(\s*[\=\-])")


# ----------------------------------------------------------------------
def _url_generator(url_base, data):
    """
    This functions download and URL, if pass callback function validation.

    :param url_base: Base url where looking for plugins
    :type url_base: basestring

    :param data: list with plugin info. This list comes from csv iteration. Format:
        data[0] => plugin uri
        data[1] => plugin name
        data[2] => plugin last version
        data[3] => CVEs, separated by "|" character.
    :type data: list

    :return: list of URLs generated
    :rtype: list(str)
    """

    urls_plugin_regex = {
        "readme.txt": exp,
        "README.txt": exp,
    }

    results = []
    # Test each URL with possible plugin version info
    for target, regex in urls_plugin_regex.items():

        _path = "wp-content/plugins/%s/%s" % (data[0], target)

        # Make Plugin url
        results.append(urljoin(url_base, _path))

    return results


# ----------------------------------------------------------------------
def _plugin_analyze(data_map, error_page, db, log, url, headers, status, content):
    """
    This functions download and URL, if pass callback function validation.

    :param data_map: a dict with with plugin info, into a list. This list comes from csv iteration. Format:
        {
            plugin_name: [
                    [0] => plugin uri
                    [1] => plugin name
                    [2] => plugin last version
                    [3] => CVEs, separated by "|" character.
                ]
        }
    :type data_map: dict(str: list)

    :param error_page: Error page content as raw.
    :type error_page: basestring

    :param db: cve database instance
    :type db: DB

    :param log: logging function, as format: log(message, level)
    :type log: function

    :param url: current plugin URL to analyze
    :type url: str

    :param headers: dict with HTTP headers response
    :type headers: dict

    :param status: HTTP status response
    :type status: int

    :param content: Response of HTTP query
    :type content: str

    :return: PlecostPluginInfo instance
    :rtype: PlecostPluginInfo|None
    """
    if content is None:
        return None

    data = data_map[url]

    # Plugin properties
    plugin_uri, plugin_name, plugin_last_version = data

    # --------------------------------------------------------------------------
    # Looking for plugin info
    # --------------------------------------------------------------------------
    plugin_installed_version = None
    if status == 403:  # Installed, but inaccessible
        plugin_installed_version = "Unknown"
    elif status == 200:
        # Check if page is and non-generic not found page with 404 code
        if get_diff_ratio(error_page, content) < 0.52:
            # Find the version
            tmp_version = exp.search(content)

            if tmp_version is not None:
                plugin_installed_version = tmp_version.group(2)

            # Try to improve version, looking for into changelog
            if plugin_installed_version is None or plugin_installed_version == "trunk":

                tmp_version_change_log = exp_change_log.search(content)

                if tmp_version_change_log is not None:
                    plugin_installed_version = tmp_version_change_log.group(2)

    # Store info
    if plugin_installed_version is not None:

        # --------------------------------------------------------------------------
        # Looking for CVE
        # --------------------------------------------------------------------------
        cves = db.query_plugin(plugin_uri.replace("_", "-"),
                               plugin_name,
                               plugin_installed_version)

        plugin = PlecostPluginInfo(current_version=plugin_installed_version,
                                   last_version=plugin_last_version,
                                   plugin_name=plugin_name,
                                   plugin_uri=url,
                                   cves=cves)
        text = ("\n    <%(symbol)s> Plugin found: %(name)s\n"
                "        |_Latest version: %(last)s\n"
                "        |_Installed version: %(curr)s"
                ) % {
                   "symbol": colorize("!", "red") if plugin.is_outdated else "i",
                   "name": colorize(plugin.plugin_name, "blue"),
                   "last": colorize(plugin.latest_version),
                   "curr": colorize(plugin.current_version, "red") if plugin.is_outdated else plugin.current_version}

        # Print
        log(text)

        # Print CVE list
        if plugin.cves:
            log("\n        |_CVE list:\n")
            for cve in list(set(plugin.cves)):
                text = (
                           "        |__%(cve)s: (http://cve.mitre.org/cgi-bin/cvename.cgi?name=%(cve)s)\n"
                       ) % {"cve": colorize(cve, "red")}

                log(text)
        else:
            text = (
                       "\n        |_CVEs: %(text)s"
                   ) % {"text": colorize("NO CVEs found for this plugin",
                                         "green")}
            log(text)

        return plugin  # Plugin found -> not more URL test for this plugin

    else:
        return None


# ----------------------------------------------------------------------
@asyncio.coroutine
def plugins_testing(url,
                    session,
                    error_page,
                    log,
                    data_list,
                    db,
                    concurrency=4,
                    ignore_403=False,
                    loop=None,
                    con=None):
    """
    Try to find plugins in remote url

    :param url: Base url to test the URL list
    :type url: str

    :param data_list: list of urls to test
    :type data_list: list

    :param db: cve database instance
    :type db: DB

    :param concurrency: max concurrency to process URLs
    :type concurrency: int

    :return: URLs of plugins and if pass check function or not. Format: [("url_to_plugin", True)]
    :rtype: list((str, Bool))
    """
    if not isinstance(url, str):
        raise TypeError("Expected basestring, got '%s' instead" % type(url))
    if not isinstance(concurrency, int):
        raise TypeError("Expected int, got '%s' instead" % type(concurrency))

    # Make URLs
    urls = {}
    for x in data_list:
        for u in _url_generator(url, x):
            urls[u] = x

    # Map function
    fn = partial(_plugin_analyze, urls, error_page, db, log)

    # Prepare concurrent connections
    cr = ConcurrentDownloader(fn,
                              session=session,
                              max_tasks=concurrency,
                              loop=loop,
                              ignore_403=ignore_403,
                              max_redirects=0)
    cr.add_url_list(urls)

    # Run and wait!
    yield from cr.run()

    return cr.results


__all__ = ("plugins_testing", )

