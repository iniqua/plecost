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
This file contains Plecost exceptions
"""


# --------------------------------------------------------------------------
class PlecostWordListNotFound(Exception):
    """Word list not found"""


# --------------------------------------------------------------------------
class PlecostTargetNotAvailable(Exception):
    """Impossible to connect to the target"""


# --------------------------------------------------------------------------
class PlecostNotWordPressFound(Exception):
    """Exception when not a valid WordPress installation found"""


# --------------------------------------------------------------------------
class PlecostInvalidReportFormat(Exception):
    """Requested report file formant is not available."""
