import json
import os

from helpers.file_manager import FileMager
from helpers.utils import get_dict_from_json_file


class CWEParser:
    # TODO dodanie CWE których nie ma
    # FIXME CamleCase
    def __init__(self, current_working_dir, src_filepath) -> None:
        self.dst_filepath = FileMager.get_cwe_simplified_output_filepath(
            current_working_dir
        )
        raw_data: dict = get_dict_from_json_file(src_filepath)
        parsed_data = self.parse(raw_data)

        # zapisywanie
        with open(self.dst_filepath, "w") as f:
            json.dump(parsed_data, f, indent=4)

        # usuwanie pliku
        # os.remove(src_filepath)

    def parse(self, raw_data: dict) -> dict:
        result = []
        weakness: list = (
            raw_data.get("Weakness_Catalog").get("Weaknesses").get("Weakness")
        )

        counter = 1
        for w in weakness:
            try:  # mismash json
                extended_description = w["Extended_Description"].get("xhtml:p", [""])
                extended_description = (
                    extended_description[0]
                    if isinstance(extended_description, list)
                    else extended_description
                )
                extended_description = extended_description.replace("\n\t\t\t\t\t", " ")
            except AttributeError:
                extended_description = w["Extended_Description"]
                extended_description = extended_description.replace("\n\t\t\t\t\t", " ")

            except KeyError:
                extended_description = (
                    None  # some CWEs don't have Extended_Description at all
                )

            cwe_code = f'CWE-{w["@ID"]}' if w["@ID"].isnumeric() else w["@ID"]
            description = w["Description"].replace("\n\t\t\t\t\t", " ")

            result.append(
                {
                    "artificialId": counter,  # needed for dummy data in JS
                    "id": cwe_code,
                    "name": w["@Name"],
                    "abstraction": w["@Abstraction"],
                    "structure": w["@Structure"],
                    "status": w["@Status"],
                    "description": description,
                    "extendedDescription": extended_description,
                }
            )
            counter += 1

        return result
