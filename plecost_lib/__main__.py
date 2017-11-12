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

import argparse

from os import environ
from traceback import format_exc


# ----------------------------------------------------------------------
def banner(version):

    return ('''
///////////////////////////////////////////////////////
// ..................................DMI...
// .............................:MMMM......
// .........................$MMMMM:........
// .........M.....,M,=NMMMMMMMMD...........
// ........MMN...MMMMMMMMMMMM,.............
// .......MMMMMMMMMMMMMMMMM~...............
// .......MMMMMMMMMMMMMMM..................
// ....?MMMMMMMMMMMMMMMN$I.................
// .?.MMMMMMMMMMMMMMMMMMMMMM...............
// .MMMMMMMMMMMMMMN........................
// 7MMMMMMMMMMMMMON$.......................
// ZMMMMMMMMMMMMMMMMMM.......libs.......
// .:MMMMMMMZ~7MMMMMMMMMO..................
// ....~+:.................................
//
// Plecost - Wordpress finger printer Tool - v%s
//
// Developed by:
//        Francisco Jesus Gomez aka ffranz | @ffranz - ffranz-[at]-iniqua.com
//        Daniel Garcia aka cr0hn | @ggdaniel - cr0hn-[at]-cr0hn.com
//
// Info: http://iniqua.com/labs/
// Repo: https://github.com/iniqua/plecost
// Bug report: libs@iniqua.com or https://github.com/iniqua/plecost/issues/
''') % version


# ----------------------------------------------------------------------
def main():

    from .api import run, __version__
    from .libs.exceptions import PlecostNotWordPressFound
    from .libs.data import PlecostOptions, PlecostDatabaseQuery
    from .libs.utils import log
    from .libs.db import db_query

    examples = '''
Examples:

    * Scan target using default 50 most common plugins:
        plecost TARGET
    * Update plugin list
        plecost --update-plugins
    * Update vulnerability database:
        plecost --update-cve
    * List available word lists:
        plecost -l
    * Use embedded 1000 most common word list:
        plecost -w plugin_list_1000.txt TARGET
        or: plecost -w plugin_list_1000 TARGET
    * Scan, using 10 concurrent network connections:
        plecost -w plugin_list_1000.txt --concurrency 10 TARGET
    * Scan using verbose mode and generate xml report:
        plecost -w plugin_list_1000.txt --concurrency 10 -o report.xml TARGET
    * Scan using verbose mode and generate json report:
        plecost -vvv --concurrency 10 -o report.json TARGET
    * Not show banner, and only test wordpress connectivity, without plugin or wordpress testing:
        plecost -v -np -nc -nv TARGET
    * Update CVE database:
        plecost --update-cve
    * Update plugins list:
        plecost --update-plugins
    * List plugins with associated vulnerabilities in local database:
        plecost --show-plugins
    '''

    parser = argparse.ArgumentParser(description='Plecost: Wordpress finger printer tool', epilog=examples,
                                     formatter_class=argparse.RawTextHelpFormatter)

    # Main options
    parser.add_argument("target", metavar="TARGET", nargs="*")
    parser.add_argument("-v", "--verbosity", dest="verbose", action="count", help="verbosity level: -v, -vv, -vvv.", default=0)
    parser.add_argument('-o', dest="OUTPUT_FILE", help="report file with extension: xml|json", default=None)

    # Scanner options
    gr_wordlist = parser.add_argument_group("scanner options")
    gr_wordlist.add_argument('--hostname', dest="HOSTNAME", default=None,
                             help="set custom hostname for the HTTP request")
    gr_wordlist.add_argument('-np', '--no-plugins', dest="NO_PLUGINS_VERSIONS", action="store_true", default=False,
                             help="do not try to find plugins versions")
    gr_wordlist.add_argument('-nc', '--no-check-wordpress', dest="NO_CHECK_WORDPRESS", action="store_true",
                             default=False, help="do not check Wordpress connectivity")
    gr_wordlist.add_argument('-nv', '--no-wordpress-version', dest="NO_CHECK_WORDPRESS_VERSION", action="store_true",
                             default=False, help="do not check Wordpress version")
    gr_wordlist.add_argument('-f', '--force-scan', dest="FORCE_SCAN", action="store_true",
                             default=False, help="force to scan even although not wordpress installation detected")
    gr_wordlist.add_argument('-j', '--jackass-modes', dest="JACKASS", action="store_true",
                             default=False, help="jackass mode: unlimited connections to remote host")

    # Wordlist
    gr_wordlist = parser.add_argument_group("wordlist options")
    gr_wordlist.add_argument('-w', '--wordlist', dest="WORDLIST", help="set custom word list. Default 200 most common",
                             default=None)
    gr_wordlist.add_argument('-l', '--list-wordlist', dest="LIST_WORDLIST", help="list embedded available word list",
                             action="store_true", default=False)

    # Performance options
    gr_performance = parser.add_argument_group("advanced options")
    gr_performance.add_argument('-c', '--concurrency', dest="CONCURRENCY", type=int, help="number of parallel processes.",
                                default=4)
    gr_performance.add_argument('--ignore-403', dest="IGNORE_403",
                                action="store_true",
                                help="ignore 403 server responses",
                                default=False)
    # gr_performance.add_argument('--proxy', dest="PROXY", help="proxy as format proxy:port.", default=None)
    gr_performance.add_argument('-nb', dest="NO_BANNER", action="store_true", help="don't display banner",
                                default=False)

    # Updater
    gr_update = parser.add_argument_group("update options")
    #gr_update.add_argument('--update-core', dest="UPDATE_CORE", action="store_true", help="Update Plecost core.", default=False)
    gr_update.add_argument('--update-cve', dest="UPDATE_CVE", action="store_true", help="Update CVE database.", default=False)
    gr_update.add_argument('--update-plugins', dest="UPDATE_PLUGINS", action="store_true",
                           help="Update plugins.", default=False)
    gr_update.add_argument('--update-all', dest="UPDATE_ALL", action="store_true", help="Update CVE, plugins, and core.", default=False)

    # Database query
    gr_query = parser.add_argument_group("database search")
    gr_query.add_argument("-sp", "--show-plugins", dest="show_plugin_list", action="store_true",
                          help="display plugins in database")
    gr_query.add_argument("-vp", "--plugin-cves", dest="show_plugin_cves", help="display CVEs for plugin")
    gr_query.add_argument("--cve", dest="cve_details", help="display details of CVE")

    args = parser.parse_args()

    # Diplay banner
    if args.NO_BANNER is True:
        print("\n// Plecost - Wordpress finger printer Tool - v%s\n" % __version__)
    else:
        print(banner(__version__))

    # Set log function
    environ["PLECOST_LOG_LEVEL"] = str(args.verbose)

    # Update self
    # if args.UPDATE_CORE:
    #     from libs.updaters import update_core
    #     update_core(log)
    #     exit(0)

    # Update CVE
    if args.UPDATE_CVE:
        from .libs.updaters import update_cve
        update_cve(log)
        exit(0)

    # Update plugins
    if args.UPDATE_PLUGINS:
        from .libs.updaters import update_plugins
        update_plugins(log)
        exit(0)

    # Update all
    if args.UPDATE_ALL:
        from .libs.updaters import update_cve, update_plugins
        # update_core(log)
        update_cve(log)
        update_plugins(log)
        exit(0)

    # List available word lists
    if args.LIST_WORDLIST:
        from .libs.wordlist import list_wordlists
        log("Available word lists:\n")

        found = False
        for i, w in enumerate(list_wordlists(), 1):
            if not w.startswith("plugin"):
                continue
            found = True
            log("   %s - %s\n" % (i, w))
        if not found:
            log("   [!] No Word lists available\n")

        log("\n")
        exit(0)

    # --------------------------------------------------------------------------
    # Data base query
    # --------------------------------------------------------------------------
    if args.show_plugin_list or \
            args.show_plugin_cves or \
            args.cve_details:

        if args.show_plugin_cves:
            _action = "plugin_cves"
        elif args.show_plugin_list:
            _action = "plugin_list"
        else:
            _action = "cve"

        print(db_query(PlecostDatabaseQuery(action=_action,
                                            parameter=args.show_plugin_cves or args.cve_details)))

        print("[*] Done!\n")
        exit(0)

    # Targets selected?
    if not args.target:
        print("[!] You must specify a valid target. Type '-h' for help.\n")
        exit(0)

    try:
        # Set config
        config = PlecostOptions(target=args.target[0],
                                hostname=args.HOSTNAME,
                                ignore_403=args.IGNORE_403,
                                concurrency=args.CONCURRENCY,
                                verbosity=args.verbose,
                                log_function=log,
                                report=args.OUTPUT_FILE,
                                wordlist=args.WORDLIST,
                                no_check_wordpress=args.NO_CHECK_WORDPRESS,
                                no_check_plugins=args.NO_PLUGINS_VERSIONS,
                                no_check_wordpress_version=args.NO_CHECK_WORDPRESS_VERSION,
                                force_scan=args.FORCE_SCAN)

        # Run Plecost
        run(config)
    except KeyboardInterrupt:
        log("[*] Exiting ...\n")
    except PlecostNotWordPressFound as e:
        print("\n[!]", e)
    except Exception as e:
        if args.verbose > 2:
            print(format_exc())
        if args.verbose > 3:
            print("\n[!] %s\n" % e)


if __name__ == "__main__" and __package__ is None:
    # --------------------------------------------------------------------------
    #
    # INTERNAL USE: DO NOT MODIFY THIS SECTION!!!!!
    #
    # --------------------------------------------------------------------------
    import sys
    import os
    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(1, parent_dir)
    import plecost_lib
    __package__ = str("plecost_lib")

    # Check Python version
    if sys.version_info < (3, 3):
        print("\n[!] You need a Python version greater than 3.3\n")
        exit(1)

    del sys, os

    main()
