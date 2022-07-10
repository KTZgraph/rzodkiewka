import os
from typing import Optional

from ..helpers import utils

class CWEDownloader:
    CWE_FILE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
    ZIP_FILENAME = "cwe_list.zip"
    CWE_FILENAME = "cwe.json"

    def __init__(self, cwe_output_filepath=None) -> None:
        cwe_xml_file: str = self.download_cwe_xml_file(URL=CWEDownloader.CWE_FILE_URL)
        self.cwe_dict = self.get_cwe_dict(cwe_xml_file)
        self._output_filepath = self.save_cwe_xml_file(self.cwe_dict, cwe_filename=cwe_output_filepath)

    @property
    def cwe(self) -> dict:
        return self.cwe_dict

    @property
    def cwe_filepath(self) -> dict:
        return self._output_filepath

    def download_cwe_xml_file(self, URL: str) -> str:
        zip_filename = utils.download_zip_file(
            URL=URL, filename=CWEDownloader.ZIP_FILENAME
        )
        extracted_file_names = utils.unzip_package(zip_filename)

        os.remove(zip_filename)
        return extracted_file_names[0]  # tylko jeden plik w zipie

    def get_cwe_dict(self, cwe_xml_file: str) -> dict:
        cwe_dict = utils.get_dict_from_xml(xml_filename=cwe_xml_file)
        # remove xml file
        os.remove(cwe_xml_file)
        return cwe_dict

    def save_cwe_xml_file(
        self, cwe_dict: dict, cwe_filename: Optional[str] = None
    ) -> str:
        filepath = cwe_filename if cwe_filename else CWEDownloader.CWE_FILENAME
        utils.save_dict_as_json(data=cwe_dict, filename=filepath)
        return filepath