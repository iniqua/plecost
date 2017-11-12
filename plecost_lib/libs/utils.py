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
This file contains some orphan functions
"""
import urllib
import aiohttp
import asyncio
import os.path as op

from urllib.parse import urljoin
from random import choice, randint
from difflib import SequenceMatcher
from string import ascii_letters, digits

try:
    from termcolor import colored
except ImportError:
    def colored(text, color):
        return text

__all__ = ["colorize", "generate_error_page", "get_diff_ratio", "get_data_folder", "check_redirects"]


# ----------------------------------------------------------------------
def log(message, log_level=0, current_log_level=None):
    """
    Auxiliary function to use as log level

    :param current_log_level: Log level selected at the moment of running the program
    :type current_log_level: int

    :param message: Message to display
    :type message: basestring

    :param log_level: log level: 0-4
    :type log_level: int
    """
    from sys import stdout
    from os import environ

    if current_log_level is None:
        try:
            _current_log_level = int(environ["PLECOST_LOG_LEVEL"])
        except KeyError:
            _current_log_level = 0
    else:
        _current_log_level = current_log_level

    if log_level <= _current_log_level:
        print(message, end='')
        stdout.flush()


# ----------------------------------------------------------------------
def colorize(text, color="yellow", activate=True):
    """
    This function return the text in a indicated color, if color is activate.

    :param text: Text to colorize
    :type text: basestring

    :param color: Color name
    :type color: basestring

    :param activate: boolean value that indicates if color is enabled.
    :type activate: bool

    :return: string with colored (if activated) text.
    :rtype: str
    """
    if activate:
        return colored(text, color)


# ----------------------------------------------------------------------
def generate_error_page(url):
    """
    Takes an URL to an existing document and generates a random URL
    to a nonexisting document, to trigger a server error.

    Example:

    >>> from libs.utils import generate_error_page
    >>> generate_error_page("http://www.site.com/index.php")
    'http://www.site.com/index.php.19ds_8vjX'

    :param url: Original URL.
    :type  url: str

    :return: Generated URL.
    :rtype: str
    """
    if not isinstance(url, str):
        raise TypeError("Expected basestring, got '%s' instead" % type(url))

    # Get random path
    random_path = "".join(choice(ascii_letters + digits) for _ in range(randint(5, 20)))

    return "%s/%s" % (url, random_path)


# ------------------------------------------------------------------------------
def get_diff_ratio(text1, text2):
    """
    Compare two texts and return a floating point value between 0 and 1 with
    the difference ratio, with 0 being absolutely different and 1 being
    absolutely equal - the more similar the two texts are, the closer the ratio
    will be to 1.

    ..note:
        This function was taken from Golismero project: http://github.com/golismero/golismero

    :param text1: First text to compare.
    :type text1: basestring

    :param text2: Second text to compare.
    :type text2: basestring

    :returns: Floating point value between 0 and 1.
    :rtype: float
    """

    # Solve some trivial type errors (like using None).
    if not text1:
        text1 = ""
    if not text2:
        text2 = ""

    # Trivial case, the two texts are identical.
    if text1 == text2:
        return 1.0

    # Use the difflib sequence matcher to calculate the ratio.
    m = SequenceMatcher(a=text1, b=text2)
    return m.ratio()


# ----------------------------------------------------------------------
def get_data_folder():
    """
    Return path of resources folder.

    :return: path of resources folder.
    :rtype: str
    """
    return op.abspath(op.join(op.dirname(__file__), "..", "resources"))


# ----------------------------------------------------------------------
def update_progress(values, print_function=None, prefix_text="", bar_len=40):
    """
    Creates a process bar in ASCII


    >>> for x in update_progress(range(1, 65), prefix_text="Prefix text: "):
    Prefix text: [########] 20.31%

    :param values: list or generator with items to process
    :type values: list

    :param print_function: function used to display information. By default is buildin 'print'.
    :type print_function: function

    :param prefix_text: Text to write before bar.
    :type prefix_text: str

    :param bar_len: number of characters used into bar.
    :type bar_len: int

    """
    _values = list(values)
    _len_values = len(_values)
    _var_len = bar_len
    _print = print_function or print

    for i, x in enumerate(_values, start=1):
        _percent = (i/_len_values)
        _percent_fix = int((i/_len_values) * _var_len)
        _print('\r{0} [#{1}] {2:.2f}%'.format(prefix_text, '#'*_percent_fix, _percent*100), end='')
        yield x


# ------------------------------------------------------------------------------
@asyncio.coroutine
def download(url,
             max_redirect=2,
             loop=None,
             session=None,
             method="get",
             get_content=True,
             auto_redirect=True,
             custom_hostname=None):
    """
    Download a web page content.

    :param url: path where to get information.
    :type url: basestring

    :param max_tries: maximum number of retries for each page
    :type max_tries: int

    :param connector: HTTPConnection instance
    :type connector: `HTTPConnection`

    :param loop: Event loop object
    :type loop: loop

    :param method: HTTP method to use
    :type method: str

    :param get_content: boolean value that indicates if must download content or not
    :type get_content: bool

    :return: Web page content as a tuple: (http_header, status, basestring)
    :rtype: (dict, int, str)
    """

    ret_status = None
    ret_headers = None
    ret_content = None

    custom_headers = {}
    if custom_hostname:
        custom_headers["host"] = custom_hostname

    try:
        with aiohttp.Timeout(5):
            if max_redirect < 0:
                return None, None, None

            response = yield from session.request(
                method,
                url,
                headers=custom_headers,
                allow_redirects=False)

            if response.status in (300, 301, 302, 303, 307):
                location = response.headers.get('location')
                next_url = urllib.parse.urljoin(url, location)
                if max_redirect > 0:
                    log('\n[!] redirect to %r from %r\n' % (next_url, url),
                        log_level=1)
                    if auto_redirect is True:
                        # return _loop.run_until_complete(download(next_url,
                        #                                          max_redirect=(max_redirect-1)))
                        r = yield from download(next_url,
                                                max_redirect=(max_redirect - 1))
                        return r
                    else:
                        ret_headers, ret_status, ret_content = response.headers, response.status, None
                else:
                    log('\n[!] redirect limit reached for %r from %r\n' % (next_url, url), log_level=2)

                    ret_headers, ret_status, ret_content = response.headers, response.status, None
            else:
                content = None

                if get_content:
                    content = (yield from response.read()).decode(errors="ignore")

                ret_headers, ret_status, ret_content = response.headers, response.status, content

    # Timeout error
    except Exception:
        pass

    return ret_headers, ret_status, ret_content


# --------------------------------------------------------------------------
class ConcurrentDownloader:
    """Get a list of URLs. Download their content and call user defined
    action """

    # ----------------------------------------------------------------------
    def __init__(self,
                 process_url_content,
                 session,
                 max_redirects=2,
                 max_tasks=10,
                 ignore_403=False,
                 loop=None):
        """
        :param process_url_content: function to process URL content, after it is downloaded
        :type process_url_content: function

        :param max_redirects: maximum number of redirects
        :type max_redirects: int

        :param max_tries: maximum number of HTTP retries.
        :type max_tries: int

        :param max_tasks: maximum number of concurrent tasks
        :type max_tasks: int

        :param loop: optional event loop object
        :type loop: loop

        :param ignore_403: Ignore 403 responses from server
        :type ignore_403: bool

        :param connector: aioTCPConnector object
        :type connector: aiohttp.TCPConnector


        >>> import asyncio
        >>> display=lambda x: print(x)
        >>> loop = asyncio.get_event_loop()
        >>> v = ConcurrentDownloader(url_base="http://myhost.com", process_url_content=display)
        >>> loop.run_until_complete(v.run())
        """
        self.session = session
        self.ignore_403 = ignore_403,
        self.max_redirects = max_redirects
        self.process_url_function = process_url_content or (lambda x: None)
        self.max_tasks = max_tasks
        self.loop = loop or asyncio.get_event_loop()
        self.q = asyncio.Queue(loop=self.loop)
        self.__results = []
        self.__results_append = self.results.append

    # ----------------------------------------------------------------------
    @property
    def results(self):
        return self.__results

    # ----------------------------------------------------------------------
    @asyncio.coroutine
    def _work(self):
        while True:
            # Get an URL to process
            url = yield from self.q.get()

            # Download content
            log("\n    |- Trying: %s" % colorize(url, "yellow"), log_level=1)

            headers, status, content = yield from download(url,
                                                           session=self.session,
                                                           max_redirect=self.max_redirects,
                                                           loop=self.loop)

            if self.ignore_403 is True and status == 403:
                continue
            else:
                # Processing response
                _r = self.process_url_function(url, headers, status, content)
                if _r is not None:
                    self.__results_append(_r)

            del headers, status, content

            self.q.task_done()

    # --------------------------------------------------------------------------
    #
    # Public method
    #
    # ----------------------------------------------------------------------
    def close(self):
        """Close resources."""
        self.connector.close()

    # --------------------------------------------------------------------------
    @asyncio.coroutine
    def run(self):
        """
        Start the analyzer daemon.
        """

        # Add workers
        workers = [asyncio.Task(self._work(), loop=self.loop)
                   for _ in range(self.max_tasks)]

        # Wait content of workers ends
        yield from self.q.join()

        for w in workers:
            w.cancel()

    # ----------------------------------------------------------------------
    def add_url(self, url):
        """
        Add a URL to queue to analyze

        :param url: URL to store
        :type url: str
        """
        self.q.put_nowait(url)

    # ----------------------------------------------------------------------
    def add_url_list(self, urls):
        """
        Add an URL list to processing

        :param urls: list with URLs
        :type urls: str

        """
        for x in urls:
            self.q.put_nowait(x)
