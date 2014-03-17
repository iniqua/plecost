#!/usr/bin/python
# -*- coding: utf-8 -*-

#
# Plecost: Wordpress finger printer tool.
#
# @url: http://iniqua.com/labs/
#
# @author:Francisco J. Gomez aka ffranz (http://iniqua.com/)
# @author:Daniel Garcia aka cr0hn (http://www.cr0hn.com)
#
# Code is licensed under -- GPLv2, http://www.gnu.org/licenses/gpl.html --
#

from __future__ import print_function  # Python 3 compatibility

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

import argparse

from functools import partial
from traceback import format_exc
from sys import stdout

from api import run
from plecost.data import PlecostOptions
from plecost.wordlist import *


#----------------------------------------------------------------------
def log_function(current_log_level, message, log_level=0):
    """
    Auxiliary function to use as log level

    :param current_log_level: Log level selected at the moment of running the program
    :type current_log_level: int

    :param message: Message to display
    :type message: basestring
    
    :param log_level: log level: 0-4
    :type log_level: int
    """
    if log_level <= current_log_level:
        print(message, end='')
        stdout.flush()


if __name__ == '__main__':

    print('''
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
// ZMMMMMMMMMMMMMMMMMM.......plecost.......
// .:MMMMMMMZ~7MMMMMMMMMO..................
// ....~+:.................................
//
// Plecost - Wordpress finger printer Tool - v0.3.0
//
// Developed by:
//        Francisco Jesus Gomez aka ffranz | @ffranz - ffranz-[at]-iniqua.com
//        Daniel Garcia aka cr0hn | @ggdaniel - cr0hn-[at]-cr0hn.com
//
// Info: http://iniqua.com/labs/
// Bug report: plecost@iniqua.com
''')

    examples = '''
Examples:

    * Scan target using default 200 most common plugins:
        plecost TARGET
    * List available word lists:
        plecost --list-wordlist
    * Use embedded 2000 most commont word list:
        plecost -w plugin_list_2000.txt TARGET
    * Scan, using 10 concurrent network connections:
        plecost -w plugin_list_2000.txt --concurrency 10 TARGET
    * Scan using verbose mode and generate xml report:
        plecost -w plugin_list_2000.txt --concurrency 10 -o report.xml TARGET
    * Scan using verbose mode and generate json report:
        plecost -vvv --concurrency 10 -o report.json TARGET
    '''

    #parser = argparse.ArgumentParser(description='Plecost: Wordpress finger printer tool')
    parser = argparse.ArgumentParser(description='Plecost: Wordpress finger printer tool', epilog=examples,
                                     formatter_class=argparse.RawTextHelpFormatter)

    # Main options
    parser.add_argument("target", metavar="TARGET", nargs="*")
    parser.add_argument("-v", "--verbose", action="count", help="increase output verbosity", default=0)
    parser.add_argument('-o', dest="OUTPUT_FILE", help="report file with extension: xml|json", default=None)
    #parser.add_argument('--no-color', dest="NO_COLOR", action="store_true", help="don't colorize console output", default=False)

    # Wordlist
    gr_wordlist = parser.add_argument_group("wordlist options")
    gr_wordlist.add_argument('-w', '--wordlist', dest="WORDLIST", help="set custom word list. Default 200 most common",
                             default=None)
    gr_wordlist.add_argument('--list-wordlist', dest="LIST_WORDLIST", help="list embedded available word list",
                             action="store_true", default=False)

    # Performance options
    gr_performance = parser.add_argument_group("advanced options")
    gr_performance.add_argument('--concurrency', dest="CONCURRENCY", type=int, help="number of parallel processes.",
                                default=4)
    gr_performance.add_argument('--proxy', dest="PROXY", help="proxy as format proxy:port.", default=None)

    # Updater
    gr_update = parser.add_argument_group("update options")
    #gr_update.add_argument('--update-core', dest="UPDATE_CORE", type=int, help="Update Plecost core.", default=False)
    gr_update.add_argument('--update-cve', dest="UPDATE_CVE", type=int, help="Update CVE database.", default=False)
    gr_update.add_argument('--update-plugins', dest="UPDATE_PLUGINS", action="store_true",
                           help="Update plugins.", default=False)
    gr_update.add_argument('--update-all', dest="UPDATE_ALL", type=int, help="Update CVE, plugins, and core.", default=False)

    args = parser.parse_args()

    # Set log function
    log = partial(log_function, args.verbose)

    # Update self
    # if args.UPDATE_CORE:
    #     from plecost.updaters import update_core
    #     update_core(log)
    #     exit(0)

    # Update CVE
    if args.UPDATE_CVE:
        from plecost.updaters import update_cve
        update_cve(log)
        exit(0)

    # Update plugins
    if args.UPDATE_CVE:
        from plecost.updaters import update_plugins
        update_plugins(log)
        exit(0)

    # Update all
    if args.UPDATE_ALL:
        from plecost.updaters import *  #noqa
        update_core(log)
        update_cve(log)
        update_plugins(log)
        exit(0)

    # List available word lists
    if args.LIST_WORDLIST:
        from plecost.wordlist import list_wordlists
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

    # Targets selected?
    if not args.target:
        print("[!] You must specify a valid target. Type '-h' for help.\n")
        exit(0)

    try:
        # Set config
        config = PlecostOptions(proxy=args.PROXY,
                                target=args.target[0],
                                concurrency=args.CONCURRENCY,
                                verbosity=args.verbose,
                                log_function=log,
                                report=args.OUTPUT_FILE,
                                wordlist=args.WORDLIST)

        # Run Plecost
        run(config)
    except Exception, e:
        if args.verbose > 3:
            print(format_exc())
        print("[!] %s\n" % e)