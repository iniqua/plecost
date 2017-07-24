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


"""
This file contains reporting functions.
"""

import json

from abc import ABCMeta, abstractmethod
from os.path import splitext
from xml.etree import ElementTree as ET


from .exceptions import PlecostInvalidReportFormat


# --------------------------------------------------------------------------
# Abstract
# --------------------------------------------------------------------------
class Reporter(object, metaclass=ABCMeta):
    """Reporter abstract class"""

    # ----------------------------------------------------------------------
    def __init__(self, output_filename):
        """
        :param output_filename: Output file name.
        :type output_filename: str
        """
        if not isinstance(output_filename, str):
            raise TypeError("Expected basestring, got '%s' instead" % type(output_filename))

        self.__output_filename = output_filename

    # ----------------------------------------------------------------------
    @property
    def output_filename(self):
        """
        :return: output file name.
        :rtype: str
        """
        return self.__output_filename

    # ----------------------------------------------------------------------
    # Abstract methods
    # ----------------------------------------------------------------------
    @abstractmethod
    def generate(self, info):
        """
        Generates content of report

        :param info: PlecostResults instance
        :type info: `PlecostResults`

        :return: content of report
        :rtype: object

        """
        raise NotImplemented()

    # ----------------------------------------------------------------------
    @abstractmethod
    def save(self, content):
        """
        Save the the content of report into output_file

        :param content: object with content
        :type content: object
        """
        raise NotImplemented()


# --------------------------------------------------------------------------
# Implementation
# --------------------------------------------------------------------------
class ReporterJSON(Reporter):
    """JSON reporter"""

    # ----------------------------------------------------------------------
    def generate(self, info):
        """
        Generates content of report

        :param info: PlecostResults instance
        :type info: `PlecostResults`
        """
        js_info = {}

        # Set target
        js_info["target"] = info.target

        # Set time info
        js_info["start_time"] = info.start_time.strftime("%H-%m-%Y %H:%M:%S")
        js_info["end_time"] = info.end_time.strftime("%H-%m-%Y %H:%M:%S")

        # WordPress info
        js_info["wordpress"] = {
            "current_version": info.wordpress_info.current_version,
            "last_version": info.wordpress_info.latest_version,
            "outdated": info.wordpress_info.is_outdated,
            "cves": [x for x in info.wordpress_info.vulnerabilities]
        }

        # Plugins info
        js_info["plugins"] = []
        for plugin in info.plugins:

            json_plugin = {}
            json_plugin["plugin_name"] = plugin.plugin_name

            json_plugin["current_version"] = plugin.current_version
            json_plugin["last_version"] = plugin.latest_version
            json_plugin["url"] = plugin.plugin_uri
            json_plugin["outdated"] = plugin.is_outdated

            # Set CVE
            json_plugin["cves"] = [cve for cve in plugin.cves]

            # Set exploits
            json_plugin["exploits"] = [exploit for exploit in plugin.exploits]

            js_info["plugins"].append(json_plugin)

        return js_info

    # ----------------------------------------------------------------------
    def save(self, content):
        # Save to file
        json.dump(content, open(self.output_filename, "w"))


# --------------------------------------------------------------------------
class ReporterXML(Reporter):
    """XML reporter"""

    # ----------------------------------------------------------------------
    def generate(self, info):
        """
        Generates content of report

        :param info: PlecostResults instance
        :type info: `PlecostResults`
        """
        root = ET.Element("libs")

        # Set target
        target = ET.SubElement(root, "target")
        target.text = info.target

        # Set time info
        time_start = ET.SubElement(root, "start_time")
        time_start.text = info.start_time.strftime("%H-%m-%Y %H:%M:%S")

        time_end = ET.SubElement(root, "end_time")
        time_end.text = info.end_time.strftime("%H-%m-%Y %H:%M:%S")

        # WordPress info
        wordpress = ET.SubElement(root, "wordpress")
        wordpress.set("current_version", info.wordpress_info.current_version)
        wordpress.set("last_version", info.wordpress_info.latest_version)

        # Set CVE
        if info.wordpress_info.vulnerabilities:
            cves = ET.SubElement(wordpress, "cves")
            for cve in info.wordpress_info.vulnerabilities:
                xml_cve = ET.SubElement(cves, "cve")
                xml_cve.text = cve

        # Plugins info
        plugins = ET.SubElement(root, "plugins")
        for plugin in info.plugins:
            xml_plugin = ET.SubElement(plugins, "plugin")
            xml_plugin.text = plugin.plugin_name

            xml_plugin.set("current_version", plugin.current_version)
            xml_plugin.set("last_version", plugin.latest_version)
            xml_plugin.set("url", plugin.plugin_uri)
            xml_plugin.set("outdated", "Yes" if plugin.is_outdated else "No")

            # Set CVE
            if plugin.cves:
                cves = ET.SubElement(xml_plugin, "cves")
                for cve in plugin.cves:
                    xml_cve = ET.SubElement(cves, "cve")
                    xml_cve.text = cve

            # Set exploits
            if plugin.cves:
                exploits = ET.SubElement(xml_plugin, "exploits")
                for exploit in plugin.exploits:
                    xml_exploit = ET.SubElement(exploits, "exploits")
                    xml_exploit.text = exploit

        return root

    # ----------------------------------------------------------------------
    def save(self, content):
        # Save to file
        tree = ET.ElementTree(content)
        tree.write(self.output_filename, encoding="UTF-8")


# ----------------------------------------------------------------------
def get_reporter(filename):
    """
    Select correct reporter by their extension.

    :param filename: file name path.
    :type filename: basestring

    :return: Reporter instance
    :rtype: `Reporter`
    """
    reporters = dict(xml=ReporterXML,
                     json=ReporterJSON)

    try:
        extension = splitext(filename)[1][1:]

        return reporters[extension]
    except KeyError:
        raise PlecostInvalidReportFormat("Report format '%s' not found." % extension)


__all__ = ["Reporter", "get_reporter"]