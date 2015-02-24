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

from setuptools import setup, find_packages

files = ["resources/*"]

setup(
    name='plecost',
    version='1.0.0',
    packages=find_packages(),
    install_requires=["chardet", "termcolor", "BeautifulSoup4", "aiohttp"],
    url='https://github.com/iniqua/plecost',
    license='GPL2',
    author='Plecost team',
    author_email='libs@iniqua.com',
    package_data={'plecost_lib': files},
    entry_points={'console_scripts': [
        'plecost = plecost_lib.plecost:main',
        ]},
    description='Wordpress finger printer tool, libs search and retrieve information about the plugins versions '
                'installed in Wordpress systems. It can analyze a single URL or perform an analysis based on the '
                'results indexed by Google. Additionally displays CVE code associated with each plugin, if there.',
    classifiers=[
        'Environment :: Console',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Other Audience',
        'License :: OSI Approved :: GPL2',
        'Operating System :: MacOS',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX',
        'Programming Language :: Python :: 3',
        'Topic :: Security',
        ]
)
