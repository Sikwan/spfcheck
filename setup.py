import os
from setuptools import setup, find_packages

version = "0.1.7dev"

README = os.path.join(os.path.dirname(__file__), 'README.txt')
long_description = open(README).read() + '\n\n'

setup(name="sikwan.spfcheck",
        version=version,
        description=("A package to check SPF status"),
        long_description=long_description,
        install_requires=["dnspython", "netaddr"],
        keywords="sikwan spf spfcheck",
        author="Francois Vanderkelen",
        author_email="vanderkelen.francois@gmail.com",
        url="https://github.com/Sikwan/spfcheck",
        license="GPL",
        packages=find_packages(),
        namespace_packages=['sikwan'],
        classifiers = [
            'Development Status :: 3 - Alpha',
            'Intended Audience :: Developers',
            'Intended Audience :: System Administrators',
            'License :: OSI Approved :: GNU General Public License (GPL)',
            'Operating System :: Unix',
            'Programming Language :: Python',
            'Topic :: Software Development :: Libraries :: Python Modules',
        ]
)
