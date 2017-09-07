#!/usr/bin/env python3

from setuptools import setup

setup(name='visipfix',
      version='0.1.0',
      description='IPFIX message visualizer for Python 3.3',
      author='Brian Trammell',
      author_email='brian@trammell.ch',
      url='http://github.com/britram/python-ipfix',
      packages=['visipfix'],
      requires='ipfix',
      classifiers=["Development Status :: 3 - Alpha",
                   "Intended Audience :: Developers",
                   "License :: OSI Approved :: "
                   "GNU Lesser General Public License v3 or later (LGPLv3+)",
                   "Operating System :: OS Independent",
                   "Programming Language :: Python :: 3.3",
                   "Topic :: System :: Networking"]
      )
      
