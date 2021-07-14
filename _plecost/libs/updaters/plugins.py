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

import csv
import lxml.html

from urllib.error import URLError
from urllib.request import urlopen

from os.path import join

from ..utils import colorize, get_data_folder, update_progress


# --------------------------------------------------------------------------
def update_plugins(log):
    """
    Update data information.

    :param log: Log function as format: function(Message, Level)
    :type log: function(str, int)
    """
    # --------------------------------------------------------------------------
    # Config and vars
    # --------------------------------------------------------------------------
    wp_plugins_url = "http://wordpress.org/plugins/browse/popular/page/%s/"
    max_plugins = 1400

    file_out = join(get_data_folder(), "plugin_list_huge.txt")

    log("[*] Preparing for update plugins...\n")

    with open(file_out, "w") as out:

        already_processed = []
        already_processed_append = already_processed.append

        csv_file = csv.writer(out)

        total_plugins = 1
        searching = True

        # Looking for 85 * 14 (per page) = 1190  plugins
        for i in update_progress(range(1, 85),
                                 prefix_text="[*] Downloading plugins (slow): "):
            if searching is False:
                break

            # 6 tries for each request
            for x in range(1, 6):
                try:
                    url = wp_plugins_url % i
                    wpage = urlopen(url).read()
                    break
                except URLError as e:
                    log("[%s] %s" % (
                        colorize("!", "red"),
                        colorize("Error while getting URL: %s. Attempt %s.\n" % (url, x))
                    ))
                    # sleep(random())

                    # Maximum attempt reached
                    if x == 6:
                        log("[%s] %s" % (
                            colorize("!!", "red"),
                            colorize("Maximum time exceeded"),
                        ), 0)
                        return
                    else:
                        continue

            # Parse
            parsed_main = lxml.html.fromstring(wpage)

            for section in parsed_main.xpath('//main/article'):
                plugin_info = section.xpath(".//h2/a")[0]
                plugin_url = plugin_info.attrib.get("href")
                plugin_name = plugin_info.text

                if not plugin_name:
                    plugin_name = plugin_url

                #
                # Get plugins details
                #
                plugin_page = urlopen(plugin_url).read()

                plugin_parsed = lxml.html.fromstring(plugin_page)

                plugin_version = plugin_parsed.xpath("//div[contains(@class, 'plugin-meta')]/ul/li/strong")
                if plugin_version:
                    plugin_version = plugin_version[0].text
                else:
                    plugin_version = None

                # --------------------------------------------------------------------------
                # We have all information to continue?
                # --------------------------------------------------------------------------
                if plugin_url is None or plugin_version is None:
                    log("[%s] Not enough information to store plugin for:\n%s\n" %
                        (
                            colorize("ii", "red"),
                            plugin_info
                        ), 2)
                    continue

                # Report status
                log("    |-- %s - Processing plugin: %s\n" %
                    (
                        colorize(total_plugins),
                        plugin_url
                    ), log_level=1)

                # Write to file
                plugin_url_store = plugin_url.replace("https://wordpress.org/plugins/", "")[0:-1]
                try:
                    csv_file.writerow([plugin_url_store,
                                       plugin_name,
                                       plugin_version])
                except UnicodeEncodeError:
                    csv_file.writerow([plugin_url_store,
                                       plugin_url_store,
                                       plugin_version])

                # Save plugin
                already_processed_append(plugin_url)

                # Maximum number of plugins reached?
                total_plugins += 1

                if total_plugins >= max_plugins:
                    searching = False
                    break

    # Creates split files
    with open(file_out, "r") as all_plugins, \
            open(join(get_data_folder(), "plugin_list_10.txt"), 'w') as f_10, \
            open(join(get_data_folder(), "plugin_list_50.txt"), 'w') as f_50, \
            open(join(get_data_folder(), "plugin_list_100.txt"), 'w') as f_100, \
            open(join(get_data_folder(), "plugin_list_250.txt"), 'w') as f_250, \
            open(join(get_data_folder(), "plugin_list_1000.txt"), 'w') as f_1000:

        for i, line in enumerate(all_plugins.readlines(), start=1):

            _line = line

            if i < 11:
                f_10.write(_line)
            if i < 50:
                f_50.write(_line)
            if i < 100:
                f_100.write(_line)
            if i < 250:
                f_250.write(_line)
            if i < 1000:
                f_1000.write(_line)

    log("\n[*] Oks!\n")

