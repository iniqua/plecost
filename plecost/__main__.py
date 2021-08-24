import argparse
import asyncio

from plecost import __version__
from plecost.__run__ import async_main
from plecost.artwork import banner
from plecost.logger import Logger
from plecost.exceptions import PlecostException
from plecost.plugin import discover_plugins, PlecostPluginsConfig

CLI_EXAMPLES = '''
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
    * Not show banner, and only test wordpress connectivity, without plugin 
    or wordpress testing:
        plecost -v -np -nc -nv TARGET
    * Update CVE database:
        plecost --update-cve
    * Update plugins list:
        plecost --update-plugins
    * List plugins with associated vulnerabilities in local database:
        plecost --show-plugins
    '''



def main():
    parser = argparse.ArgumentParser(
        description='Plecost: Wordpress security tool',
        epilog=CLI_EXAMPLES,
        formatter_class=argparse.RawTextHelpFormatter)

    # Main options
    parser.add_argument("target", nargs="*")
    parser.add_argument("-v", "--verbosity",
                        action="count",
                        help="verbosity level: -v, -vv, -vvv.",
                        default=0)

    parser_plugins = parser.add_argument_group("global plugin options")
    parser_plugins.add_argument('-d', '--disable-plugin',
                                action='append',
                                help="disable selected plugins")
    parser_plugins.add_argument('-e', '--enable-plugin',
                                action='append',
                                help="only enable these plugins")

    # Scanner options
    gr_advanced = parser.add_argument_group("advanced options")
    gr_advanced.add_argument('-j', '--jackass-modes', dest="JACKASS",
                             action="store_true",
                             default=False,
                             help="jackass mode: unlimited connections to remote host")
    gr_advanced.add_argument('-c', '--concurrency', dest="CONCURRENCY",
                             type=int, help="number of parallel processes.",
                             default=4)
    gr_advanced.add_argument('--ignore-403', dest="IGNORE_403",
                             action="store_true",
                             help="ignore 403 server responses",
                             default=False)
    # gr_performance.add_argument('--proxy', dest="PROXY", help="proxy as format proxy:port.", default=None)
    gr_advanced.add_argument('-nb', dest="NO_BANNER", action="store_true",
                             help="don't display Plecost banner",
                             default=False)

    parsed = parser.parse_args()

    # -------------------------------------------------------------------------
    # Load plugins
    # -------------------------------------------------------------------------
    plugins_config = discover_plugins(
        disable_plugins=parsed.disable_plugin,
        only_enable_plugins=parsed.enable_plugin
    )

    # -------------------------------------------------------------------------
    # Add plugins CLI
    # -------------------------------------------------------------------------
    try:
        for cli in plugins_config.cli_run:
            cli(parser)
    except argparse.ArgumentError as e:
        print("[!] Two or more plugins have the conflicting in argparser "
              "arguments, using the same name parameter.\n")
        print("   ", e)
        exit(1)

    # -------------------------------------------------------------------------
    # Parse CLI
    # -------------------------------------------------------------------------
    parsed = parser.parse_args()

    if parsed.NO_BANNER is True:
        print(
            f"\n// Plecost - Wordpress finger printer Tool (v{__version__})\n",
            flush=True
        )
    else:
        print(banner(__version__), flush=True)

    # -------------------------------------------------------------------------
    # Configure Logger
    # -------------------------------------------------------------------------
    Logger.config_from_cli(parsed.verbosity)

    try:
        # Run Plecost
        asyncio.run(async_main(
            parsed.__dict__,
            plugins_config
        ))
    except KeyboardInterrupt:
        print("[*] Exiting ...")
    except PlecostException as e:
        print(f"[!] {e}")
    except Exception as e:
        print(f"[!] Unexpected exception: {e}")

if __name__ == '__main__':
    main()
