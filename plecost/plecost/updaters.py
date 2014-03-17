#!/usr/bin/python
# -*- coding: utf-8 -*-


"""
This file contains updater functions: core, plugins and some else info.
"""

__license__ = """
Copyright (c) 2014:

    Francisco Jesus Gomez aka ffranz | @ffranz - ffranz-[at]-iniqua.com
    Daniel Garcia aka cr0hn | @ggdaniel - cr0hn-[at]-cr0hn.com

All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted
provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions
and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions
and the following disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or
promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
OF THE POSSIBILITY OF SUCH DAMAGE.
"""

try:
    import cPickle as Pickle
except ImportError:
    import pickle as Pickle

import re
import csv

from time import sleep
from os.path import join
from codecs import decode
from random import randint
from urllib2 import urlopen, URLError

from chardet import detect
from BeautifulSoup import BeautifulSoup

from .utils import colorize, get_data_folder


#--------------------------------------------------------------------------
#
# All data components
#
#--------------------------------------------------------------------------
def update_cve(log):
    """
    Generate the CVE with WordPress vulns related DB and store it into pickled database.

    :param log: Log function as format: function(Message, Level)
    :type log: function(str, int)
    """
    cve_url = "http://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=wordpress"

    #--------------------------------------------------------------------------
    # Obtain CVE database
    #--------------------------------------------------------------------------
    try:
        wpage = urlopen(cve_url).read()
    except URLError, e:
        log("[%s] %s" % (
            colorize("!"),
            colorize("Can't obtain CVE database.")
            ), 0)
        log("    |- Error details: %s" % e, 3)

    try:
        wpage = decode(wpage, detect(wpage)["encoding"])
    except UnicodeEncodeError, e:
        log("[%s] %s" % (
            colorize("!"),
            colorize("Unicode error while processing CVE url.")
            ), 0)

        log("    |- Error details: %s" % e, 3)

        return None

    results = {}

    # Parse
    bs = BeautifulSoup(wpage)

    # For each plugin
    for cve_item in bs.find("div", attrs={'id': 'TableWithRules'}).findAll("tr")[1:]:
        rows = cve_item.findAll("td")
        cve_number = rows[0].find("a")["href"].split("=")[1]
        cve_description = rows[1].text.replace("\n", " ")

        results[cve_number] = cve_description

    # Store in file
    cve_file = join(get_data_folder(), "cve.dat")

    # Dump the info
    Pickle.dump(results, open(cve_file, "wb"))


#--------------------------------------------------------------------------
def update_plugins(log):
    """
    Update data information.

    :param log: Log function as format: function(Message, Level)
    :type log: function(str, int)
    """
    #--------------------------------------------------------------------------
    # Config and vars
    #--------------------------------------------------------------------------
    regex_plugin_name = re.compile(r"(http://wordpress.org/plugins/)([a-zA-Z0-9\\\s_\-`!()\[\]{};:'.,<>?«»‘’]+)([/]*\">)([a-zA-Z0-9\\\s_\-`!()\[\]{};:'.,?«»‘’]*)",
                                   re.I)  # -> Group 2 and 3
    regex_plugin_version = re.compile(r"(Version</span>[\sa-zA-Z]*)([0-9\.]+)", re.I)  # -> Group 2
    wp_plugins_url = "http://wordpress.org/plugins/browse/popular/page/%s/"
    max_plugins = 500

    file_out = join(get_data_folder(), "plugin_list.txt")
    cve_file = join(get_data_folder(), "cve.dat")

    # Load the info
    cve_info = Pickle.load(cve_file)

    with open(file_out, "w") as out:

        already_processed = []
        already_processed_append = already_processed.append

        csv_file = csv.writer(out)

        total_plugins = 1

        # Looking for 4000 plugins
        for i in xrange(1, 4000):

            # 6 tries for each request
            for x in xrange(1, 6):
                try:
                    url = wp_plugins_url % i
                    wpage = urlopen(url).read()
                except URLError, e:
                    log("[%s] %s" % (
                        colorize("!", "red"),
                        colorize("Error while getting URL: %s. Attempt %s.\n" % (url, x))
                        ), 0)
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

            log("[*] Page %s/4000 (%s)" % (colorize(str(i)), colorize(url, "blue")), 1)

            # Fix err
            try:
                wpage = decode(wpage, detect(wpage)["encoding"])
            except UnicodeEncodeError, e:
                log("[%s] Unicode error while processing url '%s'\n" % (
                    colorize("!", "red"),
                    colorize(url)
                    ), 0)

                log("    |- Error details: %s" % e, 3)
                continue

            # Parse
            bs = BeautifulSoup(wpage)

            # For each plugin
            for j, plugin_info in enumerate(bs.findAll("div", attrs={"class": "plugin-block"})):

                plugin_info = unicode(plugin_info)

                #--------------------------------------------------------------------------
                # Plugin name and URL
                #--------------------------------------------------------------------------
                plugin_n_t = regex_plugin_name.search(plugin_info)
                plugin_url = None
                plugin_name = None
                if plugin_n_t is None:
                    log("[%s] REGEX_PLUGIN_NAME can't found info for string: \n-------\n%s\n" %
                        (
                            colorize("!!!", "red"),
                            plugin_info
                        ), 4)
                else:
                    plugin_url = plugin_n_t.group(2) if len(plugin_n_t.groups()) >= 2 else None
                    plugin_name = plugin_n_t.group(4) if len(plugin_n_t.groups()) >= 4 else None

                # Coding fixes
                if plugin_name:
                    try:
                        plugin_name = decode(plugin_name, detect(plugin_name)["encoding"])
                    except UnicodeError:
                        try:
                            plugin_name = plugin_name.decode("UTF-8")
                        except UnicodeError:
                            plugin_name = plugin_url
                else:
                    plugin_name = plugin_url

                #--------------------------------------------------------------------------
                # Plugin version
                #--------------------------------------------------------------------------
                plugin_version = regex_plugin_version.search(plugin_info)
                if plugin_version is None:
                    log("[%s] REGEX_PLUGIN_VERSION can't found info for string: \n-------\n%s\n" %
                        (
                            colorize("!!!", "red"),
                            plugin_info
                        ), 3)
                else:
                    plugin_version = plugin_version.group(2)

                # Plugin is repeated and already processed?
                if plugin_url in already_processed:
                    log("[%s] Already processed plugin '%s'. Skipping\n" %
                        (
                            colorize("ii", "red"),
                            plugin_url
                        ), 4)
                    continue

                #--------------------------------------------------------------------------
                # We have all information to continue?
                #--------------------------------------------------------------------------
                if plugin_url is None or plugin_version is None:
                    log("[%s] Not enough information to store plugin for:\n%s\n" %
                        (
                            colorize("ii", "red"),
                            plugin_info
                        ), 4)
                    continue

                # Report status
                log("    |-- %s - Processing plugin: %s\n" %
                    (
                        colorize(total_plugins),
                        plugin_url
                    ), 0)

                # Looking for CVEs for this plugin
                cves = []
                for k, v in cve_info.iteritems():
                    if plugin_name.lower() in v.lower():
                        cves.append(k)

                # Write to file
                try:
                    csv_file.writerow([plugin_url, plugin_name, plugin_version, "|".join(cves)])
                except UnicodeEncodeError:
                    csv_file.writerow([plugin_url, plugin_url, plugin_version, "|".join(cves)])

                # Save plugin
                already_processed_append(plugin_url)

                # Maximum number of plugins reached?
                total_plugins += 1

                if total_plugins >= max_plugins:
                    return


#--------------------------------------------------------------------------
def update_core(log):
    """Comment"""


__all__ = [x for x in dir() if x.startswith("update")]