import os
from ..helpers.utils import get_dict_from_json_file, save_dict_as_json

class CVESplitter:
    def __init__(self, source_file="output/cve.json", output_dir="cve_output") -> None:
        self.output_dir = output_dir
        self.source_file = source_file
        self.cve_list = get_dict_from_json_file(self.source_file)
        self.splitted_dict = self.get_splitted_dict()
        self.save_files_by_cwe()

    def get_splitted_dict(self)->dict:
        result = {}
        for cve in self.cve_list:
            cwe_id = cve.get('cwe_id')
            if not cwe_id in result:
                result[cwe_id] = []
            result[cwe_id].append(cve)

        return result

    def save_files_by_cwe(self):
        if not os.path.isdir(self.output_dir) :
            os.mkdir(self.output_dir)

        for cwe in self.splitted_dict:
            save_dict_as_json(self.splitted_dict[cwe], f"{self.output_dir}\{cwe}.json")
