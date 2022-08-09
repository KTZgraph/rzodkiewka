import os
import json

from cwe.downloader import CWEDownloader
from cwe.parser import CWEParser
from cve.downloader import CVEDownloader
from cve.simplifier import CVESimplifier
from cve.splitter import CVESplitter
from cve.classifier import CVEClassifier
from helpers.file_manager import FileMager


def save_info(current_working_dir):
    raw_cwe_filepath = CWEDownloader(current_working_dir).output_filepath
    tmp_cwe_dirpath = CWEParser(current_working_dir, raw_cwe_filepath).output_dirpath

    cve_downloader = CVEDownloader(current_working_dir)
    raw_cve_filepath_list = cve_downloader.filepaths
    raw_cve_dirpath = cve_downloader.output_dirpath
    # zapisuje pliki
    cve_simplifier = CVESimplifier(current_working_dir, raw_cve_filepath_list)
    cve_filepath = cve_simplifier.cve_simplified_filepath

    # podzielenie plików ze względu na CWE
    cve_filepath_list = CVESplitter(current_working_dir, cve_filepath).cve_filepath_list
    print(cve_filepath_list)

    # usuwanie folderu "output_cwe"
    os.rmdir(tmp_cwe_dirpath)

    # usuwanie plików surowych CVE
    for filepath in raw_cve_filepath_list:
        os.remove(filepath)

    # usuwanie folderu "output_cve" z całą listą
    os.rmdir(raw_cve_dirpath)


def group_data(current_working_dir):
    cve_filepath = FileMager.get_cve_simplified_filepath(current_working_dir)
    with open(cve_filepath, "r", encoding="utf-8") as f:
        data = json.loads(f.read())

    CVEClassifier(current_working_dir, data)


if __name__ == "__main__":
    current_working_dir = os.getcwd()
    save_info(current_working_dir)
    group_data(current_working_dir)
