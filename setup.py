from setuptools import setup, find_packages

VERSION = '0.0.6'
DESCRIPTION = 'A basic package for CWEs, CVEs download and safe simplified files.'

# Setting up
setup(
    name="rzodkiewka",
    version=VERSION,
    author="pawlaczyk, rafalwojaczek",
    author_email="<dominika.pawlaczyk9@gmail.com>",
    description=DESCRIPTION,
    packages=find_packages(),
    install_requires=['requests', 'xmltodict', 'beautifulsoup4'],
    keywords=['python', 'CVE', 'CWE'],
    classifiers=[
        "Development Status :: 1 - Planning",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "Operating System :: Unix",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: Microsoft :: Windows",
    ]
)

