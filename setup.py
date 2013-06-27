#!/usr/bin/env python3

from distutils.core import setup

setup(name='ipfix',
      version='0.9',
      description='IPFIX implementation for Python 3.3+',
      author='Brian Trammell',
      author_email='brian@trammell.ch',
      url='http://github.com/britram/python-ipfix',
      packages=['ipfix'],
      package_data={'ipfix': ['iana.iespec', 'rfc5103.iespec']},
      scripts=['scripts/ipfix2csv'])