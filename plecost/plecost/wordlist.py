#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
This file manage word list
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

import pkg_resources

from .exceptions import PlecostWordListNotFound

#print(pkg_resources.resource_string('plecost', 'data/wordpress_detection.txt'))


#----------------------------------------------------------------------
def list_wordlists():
    """
    List internal word list.

    :return: list with file names
    :rtype: list(str)
    """
    return pkg_resources.resource_listdir("plecost", "data")


#----------------------------------------------------------------------
def get_wordlist(wordlist_name):
    """
    Get and iterator of specified word list.

    :param wordlist_name: Word list name
    :type wordlist_name: basestring

    :return: iterator with each line of file.
    :rtype: str
    """
    if not isinstance(wordlist_name, basestring):
        raise TypeError("Expected basestring, got '%s' instead" % type(wordlist_name))

    word_list_name = pkg_resources.resource_filename('plecost', 'data/%s' % wordlist_name)

    try:
        with open(word_list_name, "rU") as f:
            for word in f:
                yield word.replace("\n", "").replace("\r", "")
    except IOError, e:
        raise PlecostWordListNotFound("Wordlist '%s' not found. Error: %s" % (wordlist_name, e))
