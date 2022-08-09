import json

from helpers.file_manager import FileMager


class CVESplitter:
    def __init__(self, current_working_dir, src_filepath: str) -> None:
        with open(src_filepath, "r", encoding="utf-8") as f:
            data = json.loads(f.read())

        self.cve_splitted_by_cwe = self.split_cve_list_by_cwe(data)
        self.cve_filepath_list = self.save_files_by_cwe(
            current_working_dir, self.cve_splitted_by_cwe
        )

    def split_cve_list_by_cwe(self, data: list[dict]) -> dict:
        cve_splitted_by_cwe = {}
        for cve in data:
            cwe_id = cve.get("cwe")
            if not cwe_id in cve_splitted_by_cwe:
                cve_splitted_by_cwe[cwe_id] = []

            cve_splitted_by_cwe[cwe_id].append(cve)

        return cve_splitted_by_cwe

    def save_files_by_cwe(
        self, current_working_dir: str, cve_splitted_by_cwe: list[dict]
    ) -> list[str]:
        cve_filepath_list = []
        for cwe_id in cve_splitted_by_cwe:
            dst_filepath = FileMager.get_cve_output_filename(
                current_working_dir, cwe_id
            )
            with open(dst_filepath, "w", encoding="utf-8") as f:
                json.dump(cve_splitted_by_cwe[cwe_id], f, indent=4)

            cve_filepath_list.append(dst_filepath)
        return cve_filepath_list
