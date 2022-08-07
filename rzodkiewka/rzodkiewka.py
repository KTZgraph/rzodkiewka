import os

from cwe.downloader import CWEDownloader
from cwe.parser import CWEParser
from cve.downloader import CVEDownloader
from cve.simplifier import CVESimplifier


def save_info():
    current_working_dir = os.getcwd()
    raw_cwe_filepath = CWEDownloader(current_working_dir).output_filepath
    tmp_cwe_dirpath = CWEParser(current_working_dir, raw_cwe_filepath).output_dirpath

    cve_downloader = CVEDownloader(current_working_dir)
    raw_cve_filepath_list = cve_downloader.filepaths
    raw_cve_dirpath = cve_downloader.output_dirpath

    # zapisuje pliki
    CVESimplifier(current_working_dir, raw_cve_filepath_list)

    # usuwanie folderu "output_cwe"
    os.rmdir(tmp_cwe_dirpath)

    # usuwanie plików surowych CVE
    for filepath in raw_cve_filepath_list:
        os.remove(filepath)

    # usuwanie folderu "output_cve" z całą listą
    os.rmdir(raw_cve_dirpath)


if __name__ == "__main__":
    save_info()
