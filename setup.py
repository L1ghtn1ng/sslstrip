#!/usr/bin/env python3
import shutil
from setuptools import setup

shutil.copyfile("sslstrip.py", "sslstrip/sslstrip")

setup(name='sslstrip',
      version='0.9',
      description='A MITM tool that implements Moxie Marlinspike\'s HTTPS stripping attacks.',
      author='Moxie Marlinspike',
      author_email='moxie@thoughtcrime.org',
      url='http://www.thoughtcrime.org/software/sslstrip/',
      license='GPL',
      packages=["sslstrip"],
      package_dir={'sslstrip': 'sslstrip/'},
      scripts=['sslstrip/sslstrip'],
      data_files=[('share/sslstrip', ['README', 'COPYING', 'lock.ico'])],
      )
