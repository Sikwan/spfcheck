import os
from setuptools import setup, find_packages

version = "0.1b"

README = os.path.join(os.path.dirname(__file__), 'README.txt')
long_description = open(README).read() + '\n\n'

setup(name="sikwan.spfcheck",
        version=version,
        description=("A package to check SPF status"),
        long_description=long_description,
        install_requires=["dnspython", "netaddr"],
        keywords="sikwan spf spfcheck",
        author="Sikwan",
        url="https://github.com/Sikwan/spfcheck",
        license="GPL",
        packages=find_packages(),
        namespace_packages=['sikwan'],
        classifiers = [
            'Development Status :: 1 - Dev',
            'Intended Audience :: Developers',
            'Intended Audience :: System Administrators',
            'License :: OSI Approved :: GNU Gneral Public License (GPL)',
            'Operating System :: Unix',
            'Programming Language :: Python',
            'Topic :: Software Development :: Libraries :: Python Modules',
        ]
)
