import os

from whoosh.index import open_dir
from whoosh.qparser import QueryParser

HERE = os.path.dirname(__file__)


def search_cves(vender_name: str, max_items: int = 10):
    index_folder = os.path.join(HERE, "indexes")

    ix = open_dir(index_folder)

    with ix.searcher() as searcher:
        q = QueryParser("cpe", ix.schema).parse(vender_name)

        ret = searcher.search(q)

        for i in range(max_items):
            try:
                yield ret[i]

            except IndexError:
                return

