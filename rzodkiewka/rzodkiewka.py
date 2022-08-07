import os
from cwe.downloader import CWEDownloader
from cwe.parser import CWEParser

from cve.downloader import CVEDownloader


def save_info():
    current_working_dir = os.getcwd()
    raw_cwe_filepath = CWEDownloader(current_working_dir).output_filepath
    print("cwe_filepath: ", raw_cwe_filepath)

    simplified_cwe_filepath = CWEParser(
        current_working_dir, raw_cwe_filepath
    ).dst_filepath
    print("simplified_cwe_filepath: ", simplified_cwe_filepath)

    raw_cve_filepaths = CVEDownloader(current_working_dir).filepaths
    print(raw_cve_filepaths)


if __name__ == "__main__":
    save_info()
