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
#
# import re
# import csv
# import httplib
#
# from Queue import Queue
# from threading import Thread
# from functools import partial
# from datetime import datetime
# from urlparse import urlparse, urljoin
#
# from .data import *  # noqa
# from .wordlist import *  # noqa
# from .exceptions import *  # noqa
# from .utils import colorize, generate_error_page, download, get_diff_ratio, get_data_folder
#
#
# Probar a descargar el HTACCESS
# Ver si, con el usar el user agent de google el contenido es diferente -> malware (http://cantonbecker.com/work/musings/2009/how-to-search-for-backdoors-in-a-hacked-wordpress-site/)
#
#
# # ----------------------------------------------------------------------
# # Internal functions
# # ----------------------------------------------------------------------
# def _is_remote_a_wordpress(base_url, error_page, connection):
#     """
#     This functions checks if remote host contains a WordPress installation.
#
#     :param base_url: Base url
#     :type base_url: basestring
#
#     :param error_page: error page content
#     :type error_page: basestring
#
#     :param connection: HTTPConnection instance
#     :type connection: `HTTPConnection`
#
#     :return: True if target contains WordPress installation. False otherwise.
#     :rtype: bool
#     """
#     total_urls = 0
#     urls_found = 0
#
#     for url in get_wordlist("wordpress_detection.txt"):
#         total_urls += 1
#         # Fix the url for urljoin
#         path = url[1:] if url.startswith("/") else url
#         headers, status, content = download(urljoin(base_url, path), connection)
#
#         if status == 200:
#
#             # Try to detect non-default error pages
#             ratio = get_diff_ratio(content, error_page)
#             if ratio < 0.35:
#                 urls_found += 1
#
#     # If Oks > 85% continue
#     if (urls_found / float(total_urls)) < 0.85:
#         headers, status, content = download(urljoin(base_url, "/wp-admin/"), connection)
#         if status == 302 and "wp-login.php?redirect_to=" in headers.get("location", ""):
#             return True
#         elif status == 301 and "/wp-admin/" in headers.get("location", ""):
#             return True
#         elif status == 200:
#             return True
#         else:
#             return False
#     else:
#         return True
#
#
# # ----------------------------------------------------------------------
# def _get_wordpress_version(base_url, connection):
#     """
#     This functions checks remote WordPress version.
#
#     :param base_url: site to looking for WordPress version
#     :type base_url: basestring
#
#     :param connection: HTTPConnection instance
#     :type connection: `HTTPConnection`
#
#     :return: PlecostWordPressInfo instance.
#     :rtype: `PlecostWordPressInfo`
#     """
#     url_version = {
#         # Generic
#         "wp-login.php": r"(;ver=)([0-9\.]+)([\-a-z]*)",
#
#         # For WordPress 3.8
#         "wp-admin/css/wp-admin-rtl.css": r"(Version[\s]+)([0-9\.]+)",
#         "wp-admin/css/wp-admin.css": r"(Version[\s]+)([0-9\.]+)"
#     }
#
#     # --------------------------------------------------------------------------
#     #
#     # Get installed version:
#     #
#     # --------------------------------------------------------------------------
#
#     # --------------------------------------------------------------------------
#     # Method 1: Looking for in readme.txt
#     # --------------------------------------------------------------------------
#     curr_content = download(urljoin(base_url, "/readme.html"), connection)[2]
#
#     curr_ver = re.search(r"""(<br/>[\s]*[vV]ersion[\s]*)([0-9\.]*)""", curr_content)
#     if curr_ver is None:
#         curr_ver = None
#     else:
#         if len(curr_ver.groups()) != 2:
#             curr_ver = None
#         else:
#             curr_ver = curr_ver.group(2)
#
#     # --------------------------------------------------------------------------
#     # Method 1: Looking for meta tag
#     # --------------------------------------------------------------------------
#     curr_content_2 = download(base_url, connection)[2]
#
#     # Try to find the info
#     cur_ver_2 = re.search(r'''(<meta name=\"generator\" content=\"WordPress[\s]+)([0-9\.]+)''', curr_content_2)
#     if cur_ver_2 is None:
#         cur_ver_2 = None
#     else:
#         if len(cur_ver_2.groups()) != 2:
#             cur_ver_2 = None
#         else:
#             cur_ver_2 = cur_ver_2.group(2)
#
#     # --------------------------------------------------------------------------
#     # Match versions of the different methods
#     # --------------------------------------------------------------------------
#     return_current_version = "unknown"
#     if curr_ver is None and cur_ver_2 is None:
#         return_current_version = "unknown"
#     elif curr_ver is None and cur_ver_2 is not None:
#         return_current_version = cur_ver_2
#     elif curr_ver is not None and cur_ver_2 is None:
#         return_current_version = curr_ver
#     elif curr_ver is not None and cur_ver_2 is not None:
#         if curr_ver != cur_ver_2:
#             return_current_version = cur_ver_2
#         else:
#             return_current_version = curr_ver
#     else:
#         return_current_version = "unknown"
#
#     # If Current version not found
#     if return_current_version == "unknown":
#         for url_pre, regex in url_version.iteritems():
#             # URL to find wordpress version
#             url_current_version = urljoin(base_url, url_pre)
#             current_version_content = download(url_current_version, connection)[2]
#
#             # Find the version
#             tmp_version = re.search(regex, current_version_content)
#
#             if tmp_version is not None:
#                 return_current_version = tmp_version.group(2)
#                 break  # Found -> stop search
#
#     # --------------------------------------------------------------------------
#     # Get last version
#     # --------------------------------------------------------------------------
#     wordpress_connection = httplib.HTTPConnection("wordpress.org")
#
#     # URL to get last version of WordPress available
#     last_version_content = download("/download/", wordpress_connection)[2]
#
#     last_version = re.search("(WordPress&nbsp;)([0-9\.]*)", last_version_content)
#     if last_version is None:
#         last_version = "unknown"
#     else:
#         if len(last_version.groups()) != 2:
#             last_version = "unknown"
#         else:
#             last_version = last_version.group(2)
#
#     return PlecostWordPressInfo(current_version=return_current_version,
#                                 last_version=last_version)
#
#
# # ----------------------------------------------------------------------
# # Downloads functions
# # ----------------------------------------------------------------------
# def _download_plugin_simple(url_base, error_page, log, http_handler, data):
#     """
#     This functions download and URL, if pass callback function validation.
#
#     :param url_base: Base url where looking for plugins
#     :type url_base: basestring
#
#     :param error_page: Error page content as raw.
#     :type error_page: basestring
#
#     :param log: logging function, as format: log(message, level)
#     :type log: function
#
#     :param http_handler: HTTPConnection instance.
#     :type http_handler: `HTTPConnection`
#
#     :param data: list with plugin info. This list comes from csv iteration. Format:
#         data[0] => plugin uri
#         data[1] => plugin name
#         data[2] => plugin last version
#         data[3] => CVEs, separated by "|" character.
#     :type data: list
#
#     :return: PlecostPluginInfo instance
#     :rtype: PlecostPluginInfo|None
#     """
#
#     if data[0] == "quit":
#         return None
#
#     # Plugin properties
#     plugin_uri = data[0]
#     plugin_name = data[1]
#     plugin_last_version = data[2]
#     plugin_cves = [] if data[3] == "" else data[3].split("|")
#
#     # Test each URL with possible plugin version info
#     for target, regex in urls_plugin_regex.iteritems():
#
#         # Make Plugin url
#         partial_plugin_url = "%s/wp-content/plugins/%s/%s" % (url_base, data[0], target)
#
#         # Debug info
#         log("    |- Trying: %s (%s)...\n" % (colorize(data[0]), partial_plugin_url), 4)
#
#         # Download the info
#         headers, status, content = download(partial_plugin_url, http_handler)
#
#         # --------------------------------------------------------------------------
#         # Looking for plugin info
#         # --------------------------------------------------------------------------
#         plugin_installed_version = None
#         if status == 403:  # Installed, but inaccessible
#             plugin_installed_version = "Unknown"
#         elif status == 200:
#             # Check if page is and non-generic not found page with 404 code
#             if get_diff_ratio(error_page, content) < 0.52:
#                 # Find the version
#                 tmp_version = regex.search(content)
#
#                 if tmp_version is not None:
#                     plugin_installed_version = tmp_version.group(2)
#
#         # Store info
#         if plugin_installed_version is not None:
#             plugin = PlecostPluginInfo(current_version=plugin_installed_version,
#                                        last_version=plugin_last_version,
#                                        plugin_name=plugin_name,
#                                        plugin_uri=partial_plugin_url,
#                                        cves=plugin_cves)
#             text = (
#                 "    [%(symbol)s] Plugin found: %(name)s\n"
#                 "        |_Latest version: %(last)s\n"
#                 "        |_Installed version: %(curr)s\n"
#             ) % {
#                 "symbol": colorize("!", "red") if plugin.is_outdated else "i",
#                 "name": colorize(plugin.plugin_name, "blue"),
#                 "last": colorize(plugin.latest_version),
#                 "curr": colorize(plugin.current_version, "red") if plugin.is_outdated else plugin.current_version}
#
#             # Print
#             log(text, 0)
#
#             # Print CVE list
#             if plugin_cves:
#                 log("        |_CVE list:\n")
#                 for cve in plugin_cves:
#                     text = (
#                         "        |__%(cve)s: (http://cve.mitre.org/cgi-bin/cvename.cgi?name=%(cve)s)\n"
#                     ) % {"cve": colorize(cve, "red")}
#
#                     log(text, 0)
#
#             return plugin  # Plugin found -> not more URL test for this plugin
#
#     return None
#
#
# # ----------------------------------------------------------------------
# def _download_plugin_concurrent(url_base, error_page, log, in_queue, out_queue, http_handler):
#     """
#     Download an URL in a concurrent mode.
#
#     :param url_base: Base url where looking for plugins
#     :type url_base: basestring
#
#     :param error_page: Error page content as raw.
#     :type error_page: basestring
#
#     :param log: logging function, as format: log(message, level)
#     :type log: function
#
#     :param in_queue: input Queue witch receive the URLs.
#     :type in_queue: Queue
#
#     :param out_queue: output Queue witch function store the result info.
#     :type out_queue: Queue
#
#     :param http_handler: HTTPConnection instance.
#     :type http_handler: `HTTPConnection`
#     """
#     while True:
#         # Get the URL to download
#         data = in_queue.get()
#
#         # break?
#         if data[0] == "quit":
#             return
#
#         # Download
#         plugin = _download_plugin_simple(url_base, error_page, log, http_handler, data)
#
#         # Store result
#         if plugin:
#             out_queue.put(plugin, block=False)
#             out_queue.task_done()
#
#         # Set done
#         in_queue.task_done()
#
#
# # ----------------------------------------------------------------------
# def plugins_testing(host, error_page, log, data_list, concurrency=4):
#     """
#     Try to find plugins in remote host
#
#     :param host: Base host to test the URL list
#     :type host: str
#
#     :param data_list: list of urls to test
#     :type data_list: list
#
#     :param concurrency: max concurrency to process URLs
#     :type concurrency: int
#
#     :return: URLs of plugins and if pass check function or not. Format: [("url_to_plugin", True)]
#     :rtype: list((str, Bool))
#     """
#     if not isinstance(host, basestring):
#         raise TypeError("Expected basestring, got '%s' instead" % type(host))
#     if not isinstance(concurrency, int):
#         raise TypeError("Expected int, got '%s' instead" % type(concurrency))
#
#     schemes2port = dict(http=80,
#                         https=443)
#
#     # Get host name and port
#     parsed_url = urlparse(host)
#     host = parsed_url.netloc
#     url_base = parsed_url.path
#     port = schemes2port[parsed_url.scheme]
#     proxy = ""  # TODO
#
#     # If concurrency configured
#     if concurrency > 0:
#         q_in = Queue()
#         q_out = Queue()
#
#         # Concurrent method
#         for i in xrange(concurrency):
#             # Start HTTP persistent connections
#             if port == 80:  # Not SSL
#                 c = httplib.HTTPConnection(host, port)
#             else:
#                 c = httplib.HTTPSConnection(host, port)
#
#             t = Thread(target=_download_plugin_concurrent, kwargs={
#                 "url_base": url_base,
#                 "error_page": error_page,
#                 "log": log,
#                 "in_queue": q_in,
#                 "out_queue": q_out,
#                 "http_handler": c})
#             t.daemon = True
#             t.start()
#
#         add_data_function = partial(q_in.put, block=False)
#     else:
#         if port == 80:
#             c = httplib.HTTPConnection(host, port)
#         else:
#             c = httplib.HTTPSConnection(host, port)
#         add_data_function = partial(_download_plugin_simple, url_base, error_page, log, c)
#
#     results = []
#     results_append = results.append
#
#     # Process URLs
#     for url in data_list:
#         if not url:
#             continue
#         plugin = add_data_function(url)
#
#         if plugin:
#             results_append(plugin)
#
#     # If is a multiprocess, recover the results
#     if concurrency > 0:
#         # Wait for ending of queues
#         q_out.join()
#         q_in.join()
#
#         map(results_append, q_out.queue)
#
#     # Stop workers
#     add_data_function(["quit"])
#
#     return results
#
#
# # ----------------------------------------------------------------------
# # Main code of functions
# # ----------------------------------------------------------------------
# def find_versions(args):
#     """
#     Main function to run libs as version finder.
#
#     :param args: PlecostOptions object
#     :type args: `PlecostOptions`
#
#     :return: PlecostResults object.
#     :rtype: `PlecostResults`
#
#     :raises: PlecostTargetNotAvailable, PlecostNotWordPressFound
#     """
#     # --------------------------------------------------------------------------
#     # Common vars
#     # --------------------------------------------------------------------------
#     parsed_url = urlparse(args.target)
#     host = parsed_url.hostname
#     concurrency = args.concurrency
#     log = args.log_function
#     proxy = args.proxy
#     is_color = args.colorize
#     start_time = datetime.now()
#
#     # --------------------------------------------------------------------------
#     # Test availability of target
#     # --------------------------------------------------------------------------
#     try:
#         log("[*] Testing target connection... ", 0)
#
#         con = httplib.HTTPConnection(host)
#         download("/", con)
#
#         log(colorize("ok!\n"), 0)
#     except Exception, e:
#         raise PlecostTargetNotAvailable(e)
#
#     # Error page content.
#     headers, status, error_page = download(generate_error_page(host), con)
#
#     if 1==1:
#         # --------------------------------------------------------------------------
#         # Check if remote host is a WordPress
#         # --------------------------------------------------------------------------
#         log("[*] Testing for WordPress installation... ", 0)
#
#         if not _is_remote_a_wordpress("/", error_page, con):
#             raise PlecostNotWordPressFound("No WordPress installations found in '%s'." % host)
#
#         log(colorize("ok!\n"), 0)
#
#         # --------------------------------------------------------------------------
#         # Check WordPress version
#         # --------------------------------------------------------------------------
#         log("[*] Getting WordPress version... ", 0)
#
#         wordpress_version = _get_wordpress_version(host, con)
#         if wordpress_version:
#             log("%s (latest: %s)\n" %
#                 (
#                     colorize("%s" % wordpress_version.current_version, "red"),
#                     colorize("%s" % wordpress_version.latest_version)
#                 ), 0)
#         else:
#             log(colorize("Unknown!\n", "red"), 0)
#
#     # --------------------------------------------------------------------------
#     # Check the plugins
#     # --------------------------------------------------------------------------
#     # Read plugins file and remove \n and \r
#     plugins = []
#     plugins_append = plugins.append
#
#     with open(args.wordlist, "rU") as f:
#         for plugin in f:
#             plugins_append(plugin.replace("\n", "").replace("\r", ""))
#
#     # Prepare csv file
#     cve_info = csv.reader(plugins)
#
#     # Find plugins
#     log("[*] Looking for plugins (wordlist: %s) ... \n" % args.wordlist[args.wordlist.rfind("/") + 1:], 0)
#     plugins_info = plugins_testing(args.target, error_page, log, cve_info, concurrency)
#     log("[*] Done! \n", 0)
#
#     # Set finish time
#     end_time = datetime.now()
#
#     # --------------------------------------------------------------------------
#     # Clean up
#     # --------------------------------------------------------------------------
#     con.close()
#
#     # --------------------------------------------------------------------------
#     # Make results
#     # --------------------------------------------------------------------------
#     return PlecostResults(target=args.target,
#                           start_time=start_time,
#                           end_time=end_time,
#                           wordpress_info=wordpress_version,
#                           plugins=plugins_info)
#
#
# __all__ = ["find_versions", "_is_remote_a_wordpress"]