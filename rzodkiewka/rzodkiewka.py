import os
from cwe.downloader import CWEDownloader


def get_cwe():
    cwe_filepath = CWEDownloader(os.getcwd()).output_filepath
    print("cwe_filepath: ", cwe_filepath)


if __name__ == "__main__":
    get_cwe()