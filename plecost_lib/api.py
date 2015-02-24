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
This file contains API calls for all Plecost functions
"""

__version__ = "1.0.0"
__all__ = ["run"]


from .libs.reporters import *  # noqa
from .libs.data import PlecostOptions
from .libs.versions import find_versions  # noqa


# --------------------------------------------------------------------------
#
# Command line options
#
# --------------------------------------------------------------------------
def run(config):
    """
    Main function of libs:
    - Find WordPress versions
    - Find outdated plugins

    :param config: PlecostOptions option instance
    :type config: `PlecostOptions`

    :raises: PlecostTargetNotAvailable, PlecostNotWordPressFound, PlecostWordListNotFound
    """
    # Check reporter
    if config.report_filename is not None:
        # Select appropriate report.
        reporter_function = get_reporter(config.report_filename)

    # Find wordpress and plugins versions
    data = find_versions(config)

    # Generate reports
    if config.report_filename is not None:
        # Generate report
        report = reporter_function(config.report_filename)
        report.generate(data)

