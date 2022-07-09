import os

# CWE
from cwe.downloader import CWEDownloader
from cwe.simplifier import CWESimplifier

#CVE
from cve.downloader import CVEDownloader
from cve.simplifier import CVESimplifier
from cve.cve_list import CVEList
from cve.splitter import CVESplitter

from helpers.utils import save_zip_file

CWE_FILEPATH = "output\cwe.json"
CVE_FILEPATH = "output\cve.json"

def save_parsed_cwe_file()->None:
    """Downloads and save CWEs as JSON file."""
    cwe_downloader = CWEDownloader(cwe_output_filepath="output\cwe_source.json")
    cwe_simplifier = CWESimplifier(cwe_downloader, output_filepath=CWE_FILEPATH)
    save_zip_file(source_filepath=cwe_simplifier.cwe_filepath, output_filepath="cwe.zip")

def save_parsed_cve_files()->None:
    """Downloads and save CVEs to JSON files splitted by CWE ids."""
    cve_downloader = CVEDownloader()
    cve_simplifier = CVESimplifier(cve_downloader)
    cve_files_list = cve_simplifier.output_filepaths
    cve_list = CVEList(source_filepath_list=cve_files_list, output_filepath=CVE_FILEPATH)
    CVESplitter(source_file=cve_list.cve_filepath)

def main():
    if not os.path.isdir('output') :
        os.mkdir('output')
    
    if not os.path.exists(CWE_FILEPATH):
        save_parsed_cwe_file()

    if not os.path.exists(CVE_FILEPATH):
        save_parsed_cve_files()


if __name__ == "__main__":
    main()