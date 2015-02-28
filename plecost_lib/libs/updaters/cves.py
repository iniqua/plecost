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
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
# following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the
# following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
# following disclaimer in the documentation and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
# products derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#


import re
import io
import gzip
import sqlite3

from os.path import join
from urllib.error import URLError
from urllib.request import urlopen
from collections import defaultdict
from xml.etree import ElementTree as ET

from ..utils import update_progress, colorize, get_data_folder
from ..db import DB


# ----------------------------------------------------------------------
def _insert_cves(cves, con):
    """
    Insert CVE
    """
    for cve, description in cves:
        try:
            con.execute("INSERT INTO CVE (cve, cve_description) VALUES (?, ?)", (cve, description))
        except sqlite3.IntegrityError:
            pass

        yield cve


# ----------------------------------------------------------------------
def _store_plugins_vulnerabilities_in_db(data, connection, log):
    """Comment"""

    for plugin_name, version_cv in data.items():

        for plugin_version, cves in version_cv.items():

            # Store plugin info
            try:
                c = connection.execute("INSERT INTO PLUGIN_VULNERABILITIES (plugin_name, plugin_version) VALUES(?, ?)",
                                       (plugin_name, plugin_version, ))
            except sqlite3.IntegrityError:
                log("Error integrity in plugin: (%s, %s)" % (plugin_name, plugin_version), log_level=3)
                continue

            # Store CVEs
            for cve in _insert_cves(cves, connection):
                # Store relations
                connection.execute("INSERT INTO PLUGIN_VULNERABILITIES_CVE VALUES(?, ?)", (c.lastrowid, cve, ))

    connection.commit()


# ----------------------------------------------------------------------
def _store_wordpress_vulnerabilities_in_db(data, connection, log):
    """Comment"""

    for wordpress_version, cves in data.items():

        # Store plugin info
        try:
            connection.execute("INSERT INTO WORDPRESS_VULNERABILITIES VALUES(?)", (wordpress_version, ))
        except sqlite3.IntegrityError:
            log("Error integrity in wordpress version: %s" % wordpress_version, log_level=3)
            continue

        # Store CVEs
        for cve in _insert_cves(cves, connection):
            # Store relations
            connection.execute("INSERT INTO WORDPRESS_VULNERABILITIES_CVE VALUES(?, ?)", (wordpress_version, cve, ))

    connection.commit()


# ----------------------------------------------------------------------
def _generate_previous_versions(version):
    """
    Generates all versions from current to back.

    :param version: version in format: x.y.z
    :type version: str

    :return: a list with versions
    :rtype: list(str)

    """
    if not isinstance(version, str):
        return []

    res = []
    res_append = res.append

    _splited_version = version.split(".")

    if len(_splited_version) > 2:
        # Get version part: 3.0.1 -> 3.0
        _version = "%s.%s." % (_splited_version[0], _splited_version[1])

        # Get release part: 3.0.1 -> 1, and checks that is integer
        try:
            _release = int(_splited_version[2])
        except ValueError:
            return []

        if _release == 0:
            return []

        # Generate verstion 0 -> current
        for x in range(0, _release + 1):
            res_append("%s%s" % (_version, x))

        return res

    else:
        return []


# ----------------------------------------------------------------------
def _parse_vulnerabilities_from_nvd(stream, log=None, cpe=None):
    """
    Get NVD xml path, and return plugins name and return dict with info:

    Return tuple: plugins_vulns, wordpress_vulns

    Where:

    - Plugin_vulns: { PLUGIN_NAME: {VERSION: [CVE] } +
    - Wordpress_vulns: { VERSION: [CVE] }

    :return: Tuple plugins_vulns, wordpress_vulns
    :rtype: dict, dict

    """
    regex = re.compile("([\d]*\.[\d]+\.*[\d]*)")

    plugins = {}
    wordpress = defaultdict(list)

    log("        Processing file: ")

    parsed = ET.fromstring(stream)

    for x in update_progress(parsed.getchildren(), prefix_text="        Processing file: "):

        _tmp_v = x.findall(".//{http://cpe.mitre.org/language/2.0}fact-ref")

        # Parse version
        if _tmp_v is not None:

            for v in _tmp_v:
                _v_name = v.get("name")
                if "~~~wordpress~~" in _v_name or ":wordpress:" in _v_name:
                    _v_name_split = _v_name.split(":")

                    if len(_v_name_split) > 3:
                        _product = _v_name_split[3]
                    else:
                        continue

                    if len(_v_name_split) > 4:
                        _version = _v_name.split(":")[4]
                    else:
                        continue

                    if regex.match(_version):

                        cve_id = x.find(".//{http://scap.nist.gov/schema/vulnerability/0.4}cve-id").text
                        cve_description = x.find(".//{http://scap.nist.gov/schema/vulnerability/0.4}summary").text

                        # Wordpress vuln
                        if _product == "wordpress":
                            wordpress[_version].append((cve_id, cve_description))

                            # generate previous versions
                            for v in _generate_previous_versions(_version):
                                wordpress[v].append((cve_id, cve_description))

                            if _version == "3.9.3":
                                print(_version)

                        else:
                            # Plugin vulns
                            try:
                                plugins[_product][_version].append((cve_id, cve_description))
                            except KeyError:
                                plugins[_product] = defaultdict(list)
                                plugins[_product][_version].append((cve_id, cve_description))

                            # generate previous versions
                            for v in _generate_previous_versions(_version):
                                plugins[_product][v].append((cve_id, cve_description))

    return plugins, wordpress


# --------------------------------------------------------------------------
def update_cve(log, since=2013):
    """
    Generate the CVE with WordPress vulns related DB and store it into pickled database.

    :param log: Log function as format: function(Message, Level)
    :type log: function(str, int)

    :param since: get NVD since this date
    :type since: int

    :return: None
    """
    if not isinstance(since, int):
        raise TypeError("Expected int, got '%s' instead" % type(since))

    nvd_base_url = "https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-%s.xml.gz"

    log("[*] Updating CVE database...\n")

    # Create database
    db = DB(join(get_data_folder(), "cve.db"), auto_create=False)
    db.clean_db()
    db.create_db()

    # return
    for d in range(since, 2016):
        log("    Downloading NVD feed %s: \n" % d)

        _nvd_url = nvd_base_url % d

        # --------------------------------------------------------------------------
        # Obtain CVE database
        # --------------------------------------------------------------------------
        try:
            content = urlopen(_nvd_url).read()
        except URLError as e:
            log("[%s] %s" % (
                colorize("!"),
                colorize("Can't obtain CVE database.")
            ))
            log("    |- Error details: %s" % e, 3)

        # Load
        unziped_content = gzip.GzipFile(fileobj=io.BytesIO(content)).read()

        # Parse info
        p, w = _parse_vulnerabilities_from_nvd(unziped_content, log)

        log("\n")

        # Store
        _store_plugins_vulnerabilities_in_db(p, db.con, log)
        _store_wordpress_vulnerabilities_in_db(w, db.con, log)

    log("\n[*] Done!\n")
