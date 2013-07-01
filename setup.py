#!/usr/bin/env python3

from distutils.core import setup

with open('README.md') as file:
    long_description = file.read()

setup(name='ipfix',
      version='0.9',
      description='IPFIX implementation for Python 3.3+',
      long_description = long_description,
      author='Brian Trammell',
      author_email='brian@trammell.ch',
      url='http://github.com/britram/python-ipfix',
      packages=['ipfix'],
      package_data={'ipfix': ['iana.iespec', 'rfc5103.iespec']},
      scripts=['scripts/ipfix2csv'],
      classifiers=["Development Status :: 3 - Alpha",
                   "Intended Audience :: Developers",
                   "License :: OSI Approved :: "
                   "GNU Lesser General Public License v3 or later (LGPLv3+)",
                   "Operating System :: OS Independent",
                   "Programming Language :: Python :: 3.3",
                   "Topic :: System :: Networking"]
      )
      