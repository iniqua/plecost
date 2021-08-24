import zipfile
import os.path
import argparse
import urllib.request as req

from typing import List, Union, Dict

import orjson as json

from whoosh.qparser import QueryParser
from whoosh.index import open_dir, create_in
from whoosh.fields import Schema, ID, TEXT, STORED

from dataclasses import dataclass

HERE = os.path.dirname(__file__)


@dataclass
class CPE:
    cpe: str
    vulnerable: bool
    version_end_including: str or None = None
    version_end_excluding: str or None = None
    version_start_including: str or None = None
    version_start_excluding: str or None = None


@dataclass
class CVEInfo:
    cve: str
    description: str
    cpes: List[CPE]
    cvss: float or None


# -------------------------------------------------------------------------
# Update database
# -------------------------------------------------------------------------
FEED_BASE_PATH = "nvdcve-1.1-20"
FEED_DIR = os.path.abspath(os.path.join(HERE, "old_nvd_feeds"))
FEED_RECENT_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent" \
                  ".json.zip"


# -------------------------------------------------------------------------
# Update plugin data
# -------------------------------------------------------------------------
def load_cve(feed: str) -> List[CVEInfo]:
    def json_recursive_search(json_input: Union[List, Dict], lookup_key: str):
        if isinstance(json_input, dict):
            for k, v in json_input.items():
                if k == lookup_key:
                    yield v
                else:
                    yield from json_recursive_search(v, lookup_key)
        elif isinstance(json_input, list):
            for item in json_input:
                yield from json_recursive_search(item, lookup_key)

    json_info: dict = json.loads(open(feed, "r").read())

    cves = []

    for cve_data in json_info.get("CVE_Items"):

        # -------------------------------------------------------------------------
        # CVE + Description
        # -------------------------------------------------------------------------
        cve: str = cve_data["cve"]["CVE_data_meta"]["ID"]
        cve_description: str = ""

        for desc in cve_data["cve"]["description"]["description_data"]:
            if desc["lang"] == "en":
                cve_description = desc["value"]

        if "REJECT" in cve_description[:20]:
            continue

        # -------------------------------------------------------------------------
        # CVSS
        # -------------------------------------------------------------------------
        try:
            cvss = cve_data["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
        except KeyError:
            # No Base Metric V3 available
            try:
                cvss = cve_data["impact"]["baseMetricV2"]["cvssV2"][
                    "baseScore"]
            except KeyError:
                cvss = None

        # -------------------------------------------------------------------------
        # CPEs
        # -------------------------------------------------------------------------
        cpes = []
        for cpe_match in json_recursive_search(
                cve_data["configurations"]["nodes"], "cpe_match"
        ):
            for cpe in cpe_match:

                cpe_id: str = cpe["cpe23Uri"]

                if "wordpress" not in cpe_id.lower():
                    continue

                cpes.append(CPE(
                    cpe=cpe_id,
                    vulnerable=cpe["vulnerable"],
                    version_end_including=cpe.get("versionEndIncluding", None),
                    version_end_excluding=cpe.get("versionEndExcluding", None),
                    version_start_including=cpe.get("versionStartIncluding",
                                                    None),
                    version_start_excluding=cpe.get("versionStartExcluding",
                                                    None)
                ))

        # If this CVE is not related for Wordpress... skip it
        if not cpes:
            continue

        cves.append(CVEInfo(
            cve=cve,
            description=cve_description,
            cpes=cpes,
            cvss=cvss
        ))

    return cves


def indexing_cve(cves: List[CVEInfo], index_folder: str):
    schema = Schema(
        cve=ID(stored=True),
        cve_description_search=TEXT(stored=True),
        cve_description=STORED(),
        cve_cvss=STORED(),
        cpe=TEXT(stored=True),
        cpe_vulnerable=STORED(),
        cpe_version_end_including=STORED(),
        cpe_version_end_excluding=STORED(),
        cpe_version_start_including=STORED(),
        cpe_version_start_excluding=STORED(),
    )

    if any(x.startswith("_MAIN_") for x in os.listdir(index_folder)):
        ix = open_dir(index_folder)
    else:
        ix = create_in(index_folder, schema)

    writer = ix.writer()

    for cve_info in cves:
        for cpe in cve_info.cpes:
            writer.add_document(
                cve=cve_info.cve,
                cve_description=cve_info.description,
                cve_cvss=cve_info.cvss,
                cpe=cpe.cpe,
                cpe_vulnerable=cpe.vulnerable,
                cpe_version_end_including=cpe.version_end_including,
                cpe_version_end_excluding=cpe.version_end_excluding,
                cpe_version_start_including=cpe.version_start_including,
                cpe_version_start_excluding=cpe.version_start_excluding,
            )

    writer.commit()


def main():
    parser = argparse.ArgumentParser(
        description='Plecost CVE database builder')
    parser.add_argument('DB_PATH',
                        nargs="*",
                        help="database directory destination")
    parser.add_argument('-c', '--compress',
                        default=True,
                        help="compress database as .zip")
    parser.add_argument('-q', '--quiet',
                        default=False,
                        help="quiet mode")

    parsed = parser.parse_args()

    # -------------------------------------------------------------------------
    # Fix results database path
    # -------------------------------------------------------------------------
    if not parsed.DB_PATH:
        db_path = os.path.join(os.getcwd(), "plecost_cve_database")

        if not os.path.exists(db_path):
            os.mkdir(db_path)

    else:
        db_path = parsed.DB_PATH

    # -------------------------------------------------------------------------
    # Download latest feed file
    # -------------------------------------------------------------------------
    feed_downloaded = os.path.join(FEED_DIR, "nvdcve-1.1-recent.json.zip")

    req.urlretrieve(FEED_RECENT_URL, feed_downloaded)

    with zipfile.ZipFile(feed_downloaded, "r") as zip_ref:
        zip_ref.extractall(FEED_DIR)

    # -------------------------------------------------------------------------
    # Building database
    # -------------------------------------------------------------------------
    for n in [*range(2, 5), "nvdcve-1.1-recent.json"]:

        if type(n) is int:
            feed_file = os.path.join(FEED_DIR, f"{FEED_BASE_PATH}{n:>02}.json")
        else:
            feed_file = os.path.join(FEED_DIR, n)

        if not parsed.quiet:
            print(f"[*] Processing file '{feed_file}'", flush=True)

        cves = load_cve(feed_file)

        indexing_cve(cves, db_path)

    # -------------------------------------------------------------------------
    # Compress results
    # -------------------------------------------------------------------------
    if parsed.compress:

        to_compress_files = []

        for root, directories, files in os.walk(db_path):
            for filename in files:
                file_path = os.path.join(root, filename)

                to_compress_files.append(file_path)

        compressed_db_path = os.path.join(os.getcwd(), "plecost.db.zip")

        zip_file = zipfile.ZipFile(compressed_db_path, 'w')

        with zip_file:
            # writing each file one by one
            for file in to_compress_files:
                zip_file.write(file)

        if not parsed.quiet:
            print(f"[*] Plecost db wrote on: {compressed_db_path}")


# -------------------------------------------------------------------------
# Search for CVE
# -------------------------------------------------------------------------
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


class PlecostFindCVEs:
    slug = "core-cve-finder"
    name = "CVE finder"
    description = "asdfas"
    author = "Iniqua Team"

    # def cli_run(self,
    #             parser: argparse.ArgumentParser) -> argparse._ArgumentGroup:
    #     gr_wordlist = parser.add_argument_group("Plugins discovery options")
    #     gr_wordlist.add_argument('-w', '--wordlist', dest="WORDLIST",
    #                              help="set custom word list. Default 200 "
    #                                   "most common",
    #                              default=None)

    def cli_update(self,
                   parser: argparse.ArgumentParser) -> argparse._ArgumentGroup:
        cli_update = parser.add_argument_group("Plugins discovery options")
        cli_update.add_argument('DB_PATH',
                                nargs="*",
                                help="database directory destination")
        cli_update.add_argument('-c', '--compress',
                                default=True,
                                help="compress database as .zip")
        cli_update.add_argument('-q', '--quiet',
                                default=False,
                                help="quiet mode")

    async def on_start(self, **kwargs):
        print("load")

    # async def on_finding_wordpress(self, **kwargs):
    #     print("load")
    #
    # async def on_plugin_found(self, **kwargs):
    #     print("load")
    #
    # async def on_information_found(self, **kwargs):
    #     print("load")
    #
    def on_update(self):
        pass
