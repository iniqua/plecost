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
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
# following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the
# following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
# following disclaimer in the documentation and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
# products derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#



import re
import csv
import pickle

from time import sleep
from os.path import join
from codecs import decode
from random import randint
from chardet import detect
from bs4 import BeautifulSoup
from urllib.error import URLError
from urllib.request import urlopen

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
    regex_plugin_name = re.compile(r"(http[s]*://wordpress.org/plugins/)([a-zA-Z0-9\\\s_\-`!()\[\]{};:'.,<>?«»‘’]+)([/]*\">)([a-zA-Z0-9\\\s_\-`!()\[\]{};:'.,?«»‘’]*)",
                                   re.I)  # -> Group 2 and 3
    regex_plugin_version = re.compile(r"(Version</span>[\sa-zA-Z]*)([0-9\.]+)", re.I)  # -> Group 2
    wp_plugins_url = "http://wordpress.org/plugins/browse/popular/page/%s/"
    max_plugins = 1400

    file_out = join(get_data_folder(), "plugin_list_huge.txt")

    log("[*] Preparing for update plugins...\n")

    with open(file_out, "w") as out:

        already_processed = []
        already_processed_append = already_processed.append

        csv_file = csv.writer(out)

        total_plugins = 1

        # Looking for 85 * 12 (per page) = 1020  plugins
        for i in update_progress(range(1, 85), prefix_text="[*] Downloading plugins (slow): "):
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
                    sleep(randint(1, 4))

                    # Maximum attempt reached
                    if x == 6:
                        log("[%s] %s" % (
                            colorize("!!", "red"),
                            colorize("Maximum time exceeded"),
                        ), 0)
                        return
                    else:
                        continue

            # Fix err
            try:
                wpage = decode(wpage, detect(wpage)["encoding"])
            except UnicodeEncodeError as e:
                log("[%s] Unicode error while processing url '%s'\n" % (
                    colorize("!", "red"),
                    colorize(url)
                ))

                log("    |- Error details: %s" % e, 3)
                continue

            # Parse
            bs = BeautifulSoup(wpage)

            # For each plugin
            for j, plugin_info in enumerate(bs.findAll("div", attrs={"class": "plugin-block"})):

                plugin_info = str(plugin_info)

                # --------------------------------------------------------------------------
                # Plugin name and URL
                # --------------------------------------------------------------------------
                plugin_n_t = regex_plugin_name.search(plugin_info)
                plugin_url = None
                plugin_name = None
                if plugin_n_t is None:
                    log("[%s] REGEX_PLUGIN_NAME can't found info for string: \n-------\n%s\n" %
                        (
                            colorize("!!!", "red"),
                            plugin_info
                        ), 2)
                else:
                    plugin_url = plugin_n_t.group(2) if len(plugin_n_t.groups()) >= 2 else None
                    plugin_name = plugin_n_t.group(4) if len(plugin_n_t.groups()) >= 4 else None

                # Coding fixes
                if plugin_name:
                    try:
                        # plugin_name = decode(plugin_name, detect(plugin_name.encode())["encoding"])
                        plugin_name = plugin_name
                    except UnicodeError:
                        try:
                            plugin_name = plugin_name.decode("UTF-8")
                        except UnicodeError:
                            plugin_name = plugin_url
                else:
                    plugin_name = plugin_url

                # --------------------------------------------------------------------------
                # Plugin version
                # --------------------------------------------------------------------------
                plugin_version = regex_plugin_version.search(plugin_info)
                if plugin_version is None:
                    log("[%s] REGEX_PLUGIN_VERSION can't found info for string: \n-------\n%s\n" %
                        (
                            colorize("!!!", "red"),
                            plugin_info
                        ), 2)
                else:
                    plugin_version = plugin_version.group(2)

                # Plugin is repeated and already processed?
                if plugin_url in already_processed:
                    log("[%s] Already processed plugin '%s'. Skipping\n" %
                        (
                            colorize("ii", "red"),
                            plugin_url
                        ), 2)
                    continue

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
                try:
                    csv_file.writerow([plugin_url, plugin_name, plugin_version])
                except UnicodeEncodeError:
                    csv_file.writerow([plugin_url, plugin_url, plugin_version])

                # Save plugin
                already_processed_append(plugin_url)

                # Maximum number of plugins reached?
                total_plugins += 1

                if total_plugins >= max_plugins:
                    return

    # Creates splited files
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

