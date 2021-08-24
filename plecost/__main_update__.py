import argparse

from plecost.cve_search import search_cves

def main():
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

    parser = argparse.ArgumentParser(
        description='Plecost: Wordpress finger printer tool', epilog=examples,
        formatter_class=argparse.RawTextHelpFormatter)

    # Main options
    parser.add_argument("target")
    parser.add_argument('-o', '--report-filename',
                        help="report file in JSON format",
                        default=None)

    # Scanner options
    gr_wordlist = parser.add_argument_group("scanner options")
    gr_wordlist.add_argument('-np', '--no-check-plugins',
                             action="store_true", default=False,
                             help="do not try to find plugins versions")
    gr_wordlist.add_argument('-nc', '--no-check-wordpress',
                             action="store_true",
                             default=False,
                             help="do not check Wordpress connectivity")
    gr_wordlist.add_argument('-nv', '--no-wordpress-version',
                             dest="NO_CHECK_WORDPRESS_VERSION",
                             action="store_true",
                             default=False,
                             help="do not check Wordpress version")
    gr_wordlist.add_argument('-f', '--force-scan', dest="FORCE_SCAN",
                             action="store_true",
                             default=False,
                             help="force to scan even although not wordpress installation detected")
    gr_wordlist.add_argument('-j', '--jackass-modes', dest="JACKASS",
                             action="store_true",
                             default=False,
                             help="jackass mode: unlimited connections to remote host")

    # Wordlist
    gr_wordlist = parser.add_argument_group("wordlist options")
    gr_wordlist.add_argument('-w', '--wordlist', dest="WORDLIST",
                             help="set custom word list. Default 200 most common",
                             default=None)
    gr_wordlist.add_argument('-l', '--list-wordlist', dest="LIST_WORDLIST",
                             help="list embedded available word list",
                             action="store_true", default=False)

    # Performance options
    gr_performance = parser.add_argument_group("advanced options")
    gr_performance.add_argument('-c', '--concurrency', dest="CONCURRENCY",
                                type=int, help="number of parallel processes.",
                                default=4)
    gr_performance.add_argument('--ignore-403', dest="IGNORE_403",
                                action="store_true",
                                help="ignore 403 server responses",
                                default=False)
    # gr_performance.add_argument('--proxy', dest="PROXY", help="proxy as format proxy:port.", default=None)
    gr_performance.add_argument('-nb', dest="NO_BANNER", action="store_true",
                                help="don't display banner",
                                default=False)

    # Updater
    gr_update = parser.add_argument_group("update options")
    # gr_update.add_argument('--update-core', dest="UPDATE_CORE",
    # action="store_true", help="Update Plecost core.", default=False)
    gr_update.add_argument('--update-cve', dest="UPDATE_CVE",
                           action="store_true", help="Update CVE database.",
                           default=False)
    gr_update.add_argument('--update-plugins', dest="UPDATE_PLUGINS",
                           action="store_true",
                           help="Update plugins.", default=False)
    gr_update.add_argument('--update-all', dest="UPDATE_ALL",
                           action="store_true",
                           help="Update CVE, plugins, and core.",
                           default=False)

    # Database query
    gr_query = parser.add_argument_group("database search")
    gr_query.add_argument("-sp", "--show-plugins", dest="show_plugin_list",
                          action="store_true",
                          help="display plugins in database")
    gr_query.add_argument("-vp", "--plugin-cves", dest="show_plugin_cves",
                          help="display CVEs for plugin")
    gr_query.add_argument("--cve", dest="cve_details",
                          help="display details of CVE")

    args = parser.parse_args()

    # Diplay banner
    if args.NO_BANNER is True:
        print(
            "\n// Plecost - Wordpress finger printer Tool - v%s\n" % __version__)
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


if __name__ == '__main__':
    main()
