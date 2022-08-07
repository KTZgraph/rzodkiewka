import json
import os
import requests
import xmltodict
import zipfile
from typing import OrderedDict

from helpers.feed_manager import FeedManager
from helpers.file_manager import FileMager


class CWEDownloader:
    def __init__(self, current_working_dir: str) -> None:
        self.source_url = FeedManager.CWE_FILE_URL
        self.output_dirpath = FileMager.get_cwe_output_dir(current_working_dir)
        if not os.path.isdir(self.output_dirpath):
            os.mkdir(self.output_dirpath)

        self.output_filepath = FileMager.get_cwe_output_filepath(current_working_dir)
        zip_filepath = self.download(self.source_url, self.output_dirpath)
        xml_filepath = self.unzip(zip_filepath, self.output_dirpath)
        cwe_dict = self.get_json_from_xml(xml_filepath)

        # zapisywanie pliku json
        with open(self.output_filepath, "w") as f:
            json.dump(cwe_dict, f, indent=4)

        # usuwanie pliku zip
        os.remove(zip_filepath)
        # usuwanie pliku xml
        os.remove(xml_filepath)

    def download(self, URL: str, output_dirpath: str) -> str:
        # tworzy nazwę pliku zip "cwec_latest.zip"
        filename = f'{URL.split("/")[-1].split(".")[0]}.zip'
        filepath = os.path.join(output_dirpath, filename)

        data = requests.get(URL)
        with open(filepath, "wb") as f:
            f.write(data.content)

        return filepath

    def unzip(self, zip_filepath: str, output_dirpath: str) -> str:
        with zipfile.ZipFile(zip_filepath, "r") as zip_ref:
            extracted_file_names = zip_ref.namelist()
            zip_ref.extractall(output_dirpath)

        extracted_file = extracted_file_names[0]
        return os.path.join(output_dirpath, extracted_file)

    def get_json_from_xml(self, src_xml_filepath: str) -> str:
        xml_data = open(src_xml_filepath, "r", encoding="utf-8").read()
        parsed_data: OrderedDict = xmltodict.parse(xml_data)
        # słownik - trzeba sparsować
        return dict(parsed_data)
