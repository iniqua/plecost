import pickle
import os.path
import argparse
import urllib.request as req

import orjson as json

from dataclasses import dataclass

MAX_PAGES = 40
PER_PAGE = 250
BASE_URL = "https://api.wordpress.org/plugins/info/1.1/?action=query_plugins&" \
           "request[browse]=popular&request[per_page]=" \
           "{per_page}&request[page]={page}"

@dataclass
class WordpressVersion:
    name: str
    slug: str
    latest_version: str


class PlecostWordpressPluginsDiscover:
    slug = "core-plugin-version-finder"
    name = "Plugins version finder"
    description = "asdfas"
    author = "Iniqua Team"

    def cli_run(self, parser: argparse.ArgumentParser) -> argparse._ArgumentGroup:
        gr_wordlist = parser.add_argument_group("Plugins discovery options")
        gr_wordlist.add_argument('-w', '--wordlist', dest="WORDLIST",
                                 help="set custom word list. Default 200 "
                                      "most common",
                                 default=None)
        gr_wordlist.add_argument('-l', '--list-wordlist', dest="LIST_WORDLIST",
                                 help="list embedded available word list",
                                 action="store_true", default=False)

    async def on_plugin_found(self, **kwargs):
        ...

    #
    # async def on_information_found(self, **kwargs):
    #     print("load")
    #
    def on_update(self):

        plugins = []

        for page in range(1, MAX_PAGES):
            print(f"[*] Downloading page {page}", flush=True)

            url = BASE_URL.format(per_page=PER_PAGE, page=page)

            response = req.urlopen(url).read()
            json_data = json.loads(response)

            for p in json_data["plugins"]:
                plugins.append(WordpressVersion(
                    name=p["name"],
                    slug=p["slug"],
                    latest_version=p["version"]
                ))

        pickle.dump(
            plugins,
            open(os.path.join(os.getcwd(), "plugins.bin"), "wb"),
            pickle.HIGHEST_PROTOCOL
        )

    def init(self, config: dict):
        pass
