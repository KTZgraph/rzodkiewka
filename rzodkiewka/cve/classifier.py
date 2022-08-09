import json
import os
from datetime import datetime


class CVEClassifier:
    def __init__(self, current_working_dir: str, data: list[dict[str]]) -> None:
        self.current_working_dir = current_working_dir
        self.data = data
        cve_without_base_metric_v2_list = self.get_without_base_metric_v2()
        self.save_data("without_base_metric_v2.json", cve_without_base_metric_v2_list)

        cve_after_2022_07_17 = self.get_from_this_gt_date(year=2022, month=7, day=17)
        self.save_data("cve_ids_after_2022_07_17.json", cve_after_2022_07_17)

        gt_date_without_cvssv2 = self.get_gt_date_without_cvssv2(
            year=2022, month=7, day=17
        )
        self.save_data(
            "cve_after_2022_07_17_without_cvssv2.json", gt_date_without_cvssv2
        )

        cve_after_2022_07_17_with_cvssv2 = self.get_gt_date_cvssv2(
            year=2022, month=7, day=17
        )
        self.save_data(
            "cve_after_2022_07_17_with_cvssv2.json", cve_after_2022_07_17_with_cvssv2
        )

    def save_data(self, filename, classfied_data) -> str:
        dst_dir = os.path.join(self.current_working_dir, "classified")
        if not os.path.isdir(dst_dir):
            os.mkdir(dst_dir)

        filepath = os.path.join(dst_dir, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(classfied_data, f, indent=4)

        return filepath

    def get_without_base_metric_v2(self) -> list[dict[str]]:
        result = []
        for cve in self.data:
            if not cve.get("baseMetricV2"):
                # result.append(
                #     {
                #         "id": cve.get("id"),
                #         "published": cve.get("published"),
                #         "modified": cve.get("modified"),
                #     }
                # )

                result.append(cve.get("id"))

        return result

    def get_from_this_gt_date(self, year: str, month: str, day: str) -> list[dict[str]]:
        result = []
        for cve in self.data:
            # "2017-09-19T01:31Z" rok-miesiac-dzien
            published = cve.get("published").split("T")[0]
            published = datetime.strptime(published, "%Y-%m-%d")

            modified = cve.get("modified").split("T")[0]
            modified = datetime.strptime(modified, "%Y-%m-%d")

            date_point = datetime.strptime(f"{year}-{month}-{day}", "%Y-%m-%d")

            if published >= date_point:
                result.append(cve.get("id"))

        return result

    def get_gt_date_without_cvssv2(self, year: str, month: str, day: str):
        result = []
        for cve in self.data:
            # "2017-09-19T01:31Z" rok-miesiac-dzien
            published = cve.get("published").split("T")[0]
            published = datetime.strptime(published, "%Y-%m-%d")

            modified = cve.get("modified").split("T")[0]
            modified = datetime.strptime(modified, "%Y-%m-%d")

            date_point = datetime.strptime(f"{year}-{month}-{day}", "%Y-%m-%d")

            if published >= date_point:
                if not cve.get("baseMetricV2"):
                    result.append(cve.get("id"))

        return result

    def get_gt_date_cvssv2(self, year: str, month: str, day: str):
        result = []
        for cve in self.data:
            # "2017-09-19T01:31Z" rok-miesiac-dzien
            published = cve.get("published").split("T")[0]
            published = datetime.strptime(published, "%Y-%m-%d")

            modified = cve.get("modified").split("T")[0]
            modified = datetime.strptime(modified, "%Y-%m-%d")

            date_point = datetime.strptime(f"{year}-{month}-{day}", "%Y-%m-%d")

            if published >= date_point:
                if cve.get("baseMetricV2"):
                    result.append(cve.get("id"))

        return result
