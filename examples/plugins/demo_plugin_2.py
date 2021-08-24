import asyncio

import argparse


class PlecostDemoPlugin2:
    prefix = "dma"
    name = "Demo Plugin 2"
    description = "asdfas"
    author = "Daniel García"

    def cli_parser(self, parser: argparse.ArgumentParser) -> argparse._ArgumentGroup:
        gr_wordlist = parser.add_argument_group("Networking options")
        gr_wordlist.add_argument('--hostname', dest="HOSTNAME", default=None,
                                 help="set custom hostname for the HTTP "
                                      "request")
        gr_wordlist.add_argument('-np', '--no-plugins',
                                 dest="NO_PLUGINS_VERSIONS",
                                 action="store_true", default=False,
                                 help="do not try to find plugins versions")
        gr_wordlist.add_argument('-nc', '--no-check-wordpress',
                                 dest="NO_CHECK_WORDPRESS",
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


    async def on_start(self):
        await asyncio.sleep(2)
        print("load")

    # async def on_finding_wordpress(self):
    #     print("load")
    #
    # async def on_plugin_found(self):
    #     print("load")
    #
    # async def on_information_found(self):
    #     print("load")

    async def on_update(self):
        await asyncio.sleep(2)
        print("On Update")
