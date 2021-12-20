"""setup.py file."""

from setuptools import setup, find_packages

__author__ = "Guillermo Cotone <15230109+gcotone@users.noreply.github.com>"

with open("requirements.txt", "r") as fs:
    reqs = [r for r in fs.read().splitlines() if (len(r) > 0 and not r.startswith("#"))]

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="napalm-arubaos-switch",
    version="0.2.0",
    packages=find_packages(),
    author="Guillermo Cotone",
    author_email="15230109+gcotone@users.noreply.github.com",
    description="Napalm driver for ArubaOS Switches",
    long_description=long_description,
    long_description_content_type="text/markdown",

    classifiers=[
        "Topic :: Utilities",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Operating System :: POSIX :: Linux",
    ],
    url="https://github.com/napalm-automation-community/napalm-arubaos-switch/",
    include_package_data=True,
    install_requires=reqs,
)
