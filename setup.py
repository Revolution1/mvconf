#!/usr/bin/env python
"""

"""
import sys
from os import path

from setuptools import setup

from mvconf.version import version

SOURCE_ROOT = path.abspath(path.dirname(__file__))
sys.path.append(SOURCE_ROOT)

with open(path.join(SOURCE_ROOT, 'requirements.pip')) as f:
    requires = f.readlines()
    # requires = [line.strip().replace('==', ' (==') + ')' for line in requires]

setup(
    name='mvconf',
    version=version,
    url='',
    license='BSD',
    author='Revol Cai',
    author_email='revol.cai@daocloud.io',
    description='',
    long_description=__doc__,
    packages=['mvconf'],
    include_package_data=True,
    zip_safe=False,
    platforms='any',
    install_requires=requires,
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        # 'Programming Language :: Python :: 3',
        # 'Programming Language :: Python :: 3.3',
        # 'Programming Language :: Python :: 3.4',
        # 'Programming Language :: Python :: 3.5',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],
    entry_points={
        'console_scripts': ['mvconf=mvconf.mvconf:main']
    }
)
