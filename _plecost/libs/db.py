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


import difflib
import sqlite3

from os.path import exists, join

from .utils import get_data_folder
from .data import PlecostDatabaseQuery


# --------------------------------------------------------------------------
class DB:
    """DB handler"""

    # ----------------------------------------------------------------------
    def __init__(self, path, auto_create=True):
        """
        :param path: path to sqlite database
        :type path: str

        :param auto_create: auto create db if not found
        :type auto_create: bool

        :param overwrite: if database exits, overwrite them
        :type overwrite: bool

        """
        self.path = path

        # We need to create initial tables?
        if not exists(path):
            if auto_create:
                self.con = self.create_db()
            else:
                raise IOError("Database '%r' not found." % path)
        else:
            self.con = sqlite3.connect(path)

    # ----------------------------------------------------------------------
    def _get_rows(self, rows):
        _rows = rows.fetchall()
        if _rows is not None:
            return [x[0] for x in _rows]
        else:
            return None

    # ----------------------------------------------------------------------
    def _get_single_row(self, rows):
        _rows = rows.fetchone()
        if _rows is not None:
            return _rows[0]
        else:
            return None

    # ----------------------------------------------------------------------
    def query_plugin(self,
                     plugin_name,
                     plugin_long_name,
                     plugin_version=None):
        """
        Query for plugin version and return associated CVE, if exists.

        :param plugin_name: plugin name
        :type plugin_name: str

        :param plugin_version: plugin version
        :type plugin_version: str

        :return: CVE value
        :rtype: str|None
        """
        if not plugin_version:
            _plugin_version = "%"
        else:
            _plugin_version = plugin_version

        query = ["SELECT ",
                 "PVC.cve, ",
                 "PV.plugin_name, ",
                 "PV.plugin_version "

                 "FROM ",
                 "PLUGIN_VULNERABILITIES as PV, ",
                 "PLUGIN_VULNERABILITIES_CVE as PVC ",

                 "WHERE ",
                 "PV.ROWID == PVC._id AND ",
                 # "PV.plugin_name LIKE '%{}%' OR ",
                 "PV.plugin_long_name MATCH '{}' "]

        query_params = [plugin_name, plugin_long_name]

        #
        # Build complex full text queries
        #
        full_text_queries = []
        sep = " " if " " in plugin_long_name else "-"
        plugin_long_name_split = plugin_long_name.split(sep)
        for i in range(1,  len(plugin_long_name_split)):
            p = sep.join(plugin_long_name_split[i:])

            if not p:
                continue

            full_text_queries.append(
                " OR PV.plugin_long_name MATCH '{}' "
            )
            query_params.append(p)

        query.extend(full_text_queries)

        build_query = "".join(query).format(*query_params)

        r = self.con.execute(build_query)

        #
        # Try to discard false positive removing string with not appears with
        # the plugin version format.
        #
        # -> Only allowed versions with > 80% of similarity
        # -> Only store CVE for lower version of plugins
        #
        cleaned_cve = set()
        for p_cve, p_name, p_version in r.fetchall():
            if difflib.SequenceMatcher(None, plugin_version,
                                       p_version).real_quick_ratio() > 0.8 and \
                difflib.SequenceMatcher(None, plugin_name,
                                        p_name).real_quick_ratio() > 0.9:

                # Compare plugin versions
                if tuple(p_version.split(".")) >= \
                        tuple(plugin_version.split(".")):
                    cleaned_cve.add(p_cve)

        return cleaned_cve

    # ----------------------------------------------------------------------
    def query_wordpress(self, wordpress_version):
        """
        Query for wordpress version and return associated CVEs, if exists.

        :param wordpress_version: wordpress version
        :type wordpress_version: str

        :return: CVE value
        :rtype: str|None
        """
        r = self.con.execute("SELECT WVC.cve "
                             "FROM WORDPRESS_VULNERABILITIES as WV, WORDPRESS_VULNERABILITIES_CVE as WVC "
                             "WHERE WV.wordpress_version == WVC.wordpress_version AND WV.wordpress_version LIKE ?",
                             (wordpress_version,))

        return self._get_rows(r)

    # ----------------------------------------------------------------------
    def query_cve(self, cve):
        """
        Get CVE description

        :return: CVE description
        :rtype: str

        """
        r = self.con.execute("SELECT cve_description FROM CVE WHERE CVE.cve = ?", (cve, ))

        return self._get_single_row(r)

    # ----------------------------------------------------------------------
    def clean_db(self):

        # Remove existing info?
        tables = ["PLUGIN_VULNERABILITIES",
                  "PLUGIN_VULNERABILITIES_CVE",
                  "WORDPRESS_VULNERABILITIES",
                  "WORDPRESS_VULNERABILITIES_CVE",
                  "CVE"]

        for table in tables:
            self.con.execute("DROP TABLE IF EXISTS %s;" % table)

    # ----------------------------------------------------------------------
    def raw(self, query, parameters=()):
        """
        Make raw query
        """
        return self.con.execute(query, parameters)

    # ----------------------------------------------------------------------
    def create_db(self):
        """
        Creates databases used for storing information

        :return: sqlite connection
        :rtype: sqlite.Connection

        """
        tables = dict(
            q_table_vulns="CREATE VIRTUAL TABLE PLUGIN_VULNERABILITIES USING fts4 ("
                          "plugin_name TEXT NOT NULL, "
                          "plugin_long_name TEXT NOT NULL, "
                          "plugin_version TEXT NOT NULL);",

            q_table_vulns_cve="CREATE TABLE PLUGIN_VULNERABILITIES_CVE ("
            # "_id TEXT REFERENCES PLUGIN_VULNERABILITIES(_id), "
                              "_id TEXT REFERENCES PLUGIN_VULNERABILITIES(rowid), "
                              "cve TEXT REFERENCES cve(cve));",

            q_table_wordpress="CREATE TABLE WORDPRESS_VULNERABILITIES (wordpress_version TEXT PRIMARY KEY NOT NULL);",

            q_table_wordpress_cve="CREATE TABLE WORDPRESS_VULNERABILITIES_CVE ("
                                  "wordpress_version TEXT REFERENCES WORDPRESS_VULNERABILITIES(wordpress_version), "
                                  "CVE TEXT REFERENCES cve(cve));",

            q_table_cve="CREATE TABLE CVE ("
                        "cve TEXT PRIMARY KEY NOT NULL, "
                        "cve_description TEXT, "
                        "author_page TEXT);")

        con = sqlite3.connect(self.path)

        # Create tables
        for query in tables.values():
            con.execute(query)

        con.commit()

        self.con = con

        return con


# --------------------------------------------------------------------------
#
# Database query operations
#
# --------------------------------------------------------------------------

# ----------------------------------------------------------------------
def __cve_details(data, db):
    """
    Get a CVE details.
    """
    _cve = data.parameter
    _query = "SELECT cve_description FROM CVE WHERE cve LIKE ?;"

    res = []
    res_append = res.append

    # Title
    res_append("[*] Detail for CVE '%s':" % _cve)

    r = db.raw(query=_query, parameters=(_cve,)).fetchone()

    if r is not None:
        res_append("\n    %s" % r[0])

    res_append("\n")

    return "\n".join(res)


# ----------------------------------------------------------------------
def __plugin_cves(data, db):
    """
    Get CVEs of a plugin

    :param data: PlecostDatabaseQuery object
    :type data: PlecostDatabaseQuery

    :return: results of query
    :rtype: str
    """
    _plugin = data.parameter

    _query = ("SELECT DISTINCT(cve) "
              "FROM PLUGIN_VULNERABILITIES_CVE as PV, (SELECT DISTINCT(plugin_name), "
              "_id FROM PLUGIN_VULNERABILITIES WHERE plugin_name LIKE ?) as PN "
              "WHERE PN._id == PV._id")

    _query_versions = ("SELECT DISTINCT(plugin_version) "
                       "FROM PLUGIN_VULNERABILITIES AS PV, PLUGIN_VULNERABILITIES_CVE AS PC "
                       "WHERE PV._id == PC._id AND PC.cve like ?;")

    res = []
    res_append = res.append

    # Title
    res_append("[*] Associated CVEs for plugin '%s':\n" % _plugin)

    for i, x in enumerate(db.raw(query=_query, parameters=(_plugin,)).fetchall()):
        _cve = x[0]
        res_append("    { %s } - %s:\n" % (i, _cve))

        # Get associated versions
        res_append("             Affected versions:\n")
        for j, v in enumerate(db.raw(_query_versions, parameters=(_cve, )).fetchall()):
            _version = v[0]
            res_append("             <%s> - %s" % (j, _version))

    res_append("\n")

    return "\n".join(res)


# ----------------------------------------------------------------------
def __plugin_list(data, db):
    """
    Get plugin list in vulnerability database

    :param data: PlecostDatabaseQuery object
    :type data: PlecostDatabaseQuery

    :return: results of query
    :rtype: str
    """
    res = []
    res_append = res.append

    # Title
    res_append("[*] Plugins with vulnerabilities known:\n")

    for i, x in enumerate(db.raw("SELECT DISTINCT(plugin_name) FROM PLUGIN_VULNERABILITIES;").fetchall()):
        res_append("    { %s } - %s" % (i, x[0]))

    res_append("\n")

    return "\n".join(res)


# ----------------------------------------------------------------------
def db_query(data):
    """
    Query the database and return a text with the information.

    :param data: PlecostDatabaseQuery object
    :type data: PlecostDatabaseQuery

    :return: results of query
    :rtype: str

    """
    if not isinstance(data, PlecostDatabaseQuery):
        raise TypeError("Expected PlecostDatabaseQuery, got '%s' instead" % type(data))

    _actions = dict(plugin_list=__plugin_list,
                    cve=__cve_details,
                    plugin_cves=__plugin_cves)

    db = DB(join(get_data_folder(), "cve.db"))

    return _actions[data.action](data, db)