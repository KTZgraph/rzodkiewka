import os
from typing import Optional

from ..helpers.utils import save_dict_as_json


class CWESimplifier:
    CWE_FILENAME = "cwe_simplified.json"

    def __init__(self, cwe_downloader, output_filepath: Optional[str] = None) -> None:
        cwe_downloader = cwe_downloader
        self.cwe_parsed = self.parse(cwe_dict=cwe_downloader.cwe)
        # remove oryginal json file
        os.remove(cwe_downloader.cwe_filepath)
        self.cwe_output_file = self.safe_parsedd_cwe_file(
            self.cwe_parsed, output_filepath
        )

    @property
    def cwe(self) -> dict:
        return self.cwe_parsed

    @property
    def cwe_filepath(self) -> str:
        return self.cwe_output_file

    def safe_parsedd_cwe_file(
        self, cwe_data: list[dict], output_filepath: Optional[str] = None
    ) -> None:
        if output_filepath:
            save_dict_as_json(data=cwe_data, filename=output_filepath)
            return output_filepath

        save_dict_as_json(data=cwe_data, filename=self.cwe_filepath)
        return self.cwe_filename

    @staticmethod
    def _get_cwe_other() -> dict:
        return {
            "id": "NVD-CWE-Other",
            "name": "Other",
            "abstraction": "Other",
            "structure": "Other",
            "status": "Other",
            "description": "Other",
            "extended_description": "Other",
        }

    def parse(self, cwe_dict: dict) -> list[dict]:
        result = []
        weakness: list = (
            cwe_dict.get("Weakness_Catalog").get("Weaknesses").get("Weakness")
        )

        for w in weakness:

            try:  # mismash json
                extended_description = w["Extended_Description"].get("xhtml:p", [""])[0]
                # print(extended_description)
            except AttributeError:
                extended_description = w["Extended_Description"]
            except KeyError:
                extended_description = (
                    None  # some CWEs don't have Extended_Description at all
                )

            result.append(
                {
                    "id": w["@ID"],
                    "name": w["@Name"],
                    "abstraction": w["@Abstraction"],
                    "structure": w["@Structure"],
                    "status": w["@Status"],
                    "description": w["Description"],
                    "extended_description": extended_description,
                }
            )

        result.append(self._get_cwe_other())
        return result
