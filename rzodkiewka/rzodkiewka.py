import os

from rzodkiewka import CWEDownloader, CWESimplifier
from rzodkiewka import CVEDownloader, CVESimplifier, CVEList, CVESplitter

CWE_FILEPATH = "output\cwe.json"
CVE_FILEPATH = "output\cve.json"


def save_parsed_cwe_file() -> str:
    """Downloads and save CWEs as JSON file.

    Returns:
        str: path to JSON file with CWEs list
    """
    cwe_downloader = CWEDownloader(cwe_output_filepath="output\cwe_source.json")
    cwe_simplifier = CWESimplifier(cwe_downloader, output_filepath=CWE_FILEPATH)
    return cwe_simplifier.cwe_filepath


def save_parsed_cve_files() -> str:
    """Downloads and save CVEs to JSON files splitted by CWE ids.

    Returns:
        str: Dir name with CVEs list splitted by CWE ids
    """
    cve_downloader = CVEDownloader()
    cve_simplifier = CVESimplifier(cve_downloader)
    cve_files_list = cve_simplifier.output_filepaths
    cve_list = CVEList(
        source_filepath_list=cve_files_list, output_filepath=CVE_FILEPATH
    )
    cve_splitter = CVESplitter(source_file=cve_list.cve_filepath)
    return cve_splitter.output_dir


def save_info():
    cwe_filepath, output_dir = None, None

    if not os.path.isdir("output"):
        os.mkdir("output")

    if not os.path.exists(CWE_FILEPATH):
        cwe_filepath = save_parsed_cwe_file()

    if not os.path.exists(CVE_FILEPATH):
        output_dir = save_parsed_cve_files()

    if cwe_filepath and output_dir:
        return cwe_filepath, output_dir

    return CWE_FILEPATH, CVE_FILEPATH
