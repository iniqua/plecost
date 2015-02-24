#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Plecost: Wordpress finger printer tool.
#
# @url: http://iniqua.com/labs/
# @url: https://github.com/iniqua/plecost
#
# @author:Francisco J. Gomez aka ffranz (http://iniqua.com/)
# @author:Daniel Garcia aka cr0hn (http://www.cr0hn.com/me/)
#
# Code is licensed under -- GPLv2, http://www.gnu.org/licenses/gpl.html --
#

"""
This file manage word list
"""

__all__ = ["list_wordlists", "get_wordlist"]

from os import listdir
from os.path import join

from .exceptions import PlecostWordListNotFound
from .utils import get_data_folder


# ----------------------------------------------------------------------
def list_wordlists():
    """
    List internal word list.

    :return: list with file names
    :rtype: list(str)
    """
    return [x for x in listdir(get_data_folder()) if x.endswith("txt")]


# ----------------------------------------------------------------------
def get_wordlist(wordlist_name):
    """
    Get and iterator of specified word list.

    :param wordlist_name: Word list name
    :type wordlist_name: basestring

    :return: iterator with each line of file.
    :rtype: str
    """
    if not isinstance(wordlist_name, str):
        raise TypeError("Expected basestring, got '%s' instead" % type(wordlist_name))

    word_list_name = join(get_data_folder(), wordlist_name)

    try:
        with open(word_list_name, "rU") as f:
            for word in f:
                yield word.replace("\n", "").replace("\r", "")
    except IOError as e:
        raise PlecostWordListNotFound("Wordlist '%s' not found. Error: %s" % (wordlist_name, e))
