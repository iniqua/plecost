import pickle
import os.path
import urllib.request as req

import orjson as json

from plecost.models import WordpressPlugin

MAX_PAGES = 40
PER_PAGE = 250
BASE_URL = "https://api.wordpress.org/plugins/info/1.1/?action=query_plugins&" \
           "request[browse]=popular&request[per_page]=" \
           "{per_page}&request[page]={page}"

def main():

    plugins = []

    for page in range(1, MAX_PAGES):
        print(f"[*] Downloading page {page}", flush=True)

        url = BASE_URL.format(per_page=PER_PAGE, page=page)

        response = req.urlopen(url).read()
        json_data = json.loads(response)

        for p in json_data["plugins"]:
            plugins.append(WordpressPlugin(
                name=p["name"],
                slug=p["slug"],
                latest_version=p["version"]
            ))

    pickle.dump(
        plugins,
        open(os.path.join(os.getcwd(), "plugins.bin"), "wb"),
        pickle.HIGHEST_PROTOCOL
    )


if __name__ == '__main__':
    main()
