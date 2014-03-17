#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
This file contains some orphan functions
"""

__license__ = """
Copyright (c) 2014:

    Francisco Jesus Gomez aka ffranz | @ffranz - ffranz-[at]-iniqua.com
    Daniel Garcia aka cr0hn | @ggdaniel - cr0hn-[at]-cr0hn.com

All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted
provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions
and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions
and the following disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or
promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
OF THE POSSIBILITY OF SUCH DAMAGE.
"""


__all__ = ["colorize", "generate_error_page", "get_diff_ratio", "get_data_folder", "check_redirects"]

from random import choice, randint
from difflib import SequenceMatcher
from urlparse import urlparse, urljoin
from string import ascii_letters, digits

try:
    from colorizer import colored
except ImportError:
    def colored(text, color):
        return text


#----------------------------------------------------------------------
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
    else:
        return text


#----------------------------------------------------------------------
def generate_error_page(url):
    """
    Takes an URL to an existing document and generates a random URL
    to a nonexisting document, to trigger a server error.

    Example:

    >>> from plecost.utils import generate_error_page
    >>> generate_error_page("http://www.site.com/index.php")
    'http://www.site.com/index.php.19ds_8vjX'

    :param url: Original URL.
    :type  url: str

    :return: Generated URL.
    :rtype: str
    """
    if not isinstance(url, basestring):
        raise TypeError("Expected basestring, got '%s' instead" % type(url))

    # Get random path
    random_path = "".join(choice(ascii_letters + digits) for _ in xrange(randint(5, 20)))

    # Generate url
    parsed_url = urlparse(url)
    path = parsed_url.path

    return "%s%s" % (path, random_path)


#------------------------------------------------------------------------------
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

    # Check for type errors we can't fix.
    if not isinstance(text1, basestring):
        raise TypeError("Expected string, got %r instead" % type(text1))
    if not isinstance(text2, basestring):
        raise TypeError("Expected string, got %r instead" % type(text2))

    # Trivial case, the two texts are identical.
    if text1 == text2:
        return 1.0

    # Use the difflib sequence matcher to calculate the ratio.
    m = SequenceMatcher(a=text1, b=text2)
    return m.ratio()


#------------------------------------------------------------------------------
def download(path, connection, follow_redirects=True):
    """
    Download a web page content.

    :param path: path where to get information.
    :type path: basestring

    :param connection: HTTPConnection instance
    :type connection: `HTTPConnection`

    :return: Web page content as a tuple: (http_header, status, basestring)
    :rtype: (dict, int, str)
    """
    # Fix path
    if not path.startswith("/"):
        path = "/%s" % path

    connection.request("GET", path)
    r = connection.getresponse()

    headers, status, content = dict(r.getheaders()), r.status, r.read()

    if follow_redirects:
        if status in (301,302):
            path = urljoin(path, headers['location'])
            connection.request("GET", path)
            r = connection.getresponse()
            headers, status, content = dict(r.getheaders()), r.status, r.read()

    return headers, status, content


#----------------------------------------------------------------------
def get_data_folder():
    """
    Return path of data folder.

    :return: path of data folder.
    :rtype: str
    """
    import pkg_resources
    return pkg_resources.resource_filename("plecost", "data")