import json
from helpers.file_manager import FileMager


class CVEParser:
    def __init__(self, data: dict, artifical_id: int) -> None:
        self._source_data = data
        _, cwe_id = self.parse_problemtype_data()

        cve_id, published, modified, description_data = self.parse_metadata()
        self._result = {
            "artificalId": artifical_id,
            "id": cve_id,
            "cwe": cwe_id,
            "description": description_data,
            "published": published,
            "modified": modified,
            "version": self.parse_version(),
            "assigner": self.parse_assigner(),
            "dataFormat": self.parse_data_format(),
            "referenceList": self.parse_references_list(),
            "cpeList": self.parse_cpe_list(),
            "baseMetricV2": self.parse_base_metric_v2(),
            "baseMetricV3": self.parse_base_metric_v3(),
        }

    @property
    def data(self) -> dict:
        return self._result

    def parse_problemtype_data(self):
        for problemtype_data in (
            self._source_data.get("cve").get("problemtype").get("problemtype_data")
        ):
            description = problemtype_data["description"]
            cwe_id = description[0].get("value") if description else None

        return description, cwe_id

    def parse_metadata(self):
        cve_id = self._source_data["cve"]["CVE_data_meta"]["ID"]
        published = self._source_data["publishedDate"]
        modified = self._source_data["lastModifiedDate"]
        description_data = self._source_data["cve"]["description"]["description_data"][
            0
        ]["value"]
        return cve_id, published, modified, description_data

    def parse_version(self):
        return self._source_data.get("cve", {}).get("data_version")

    def parse_assigner(self):
        return self._source_data.get("cve", {}).get("CVE_data_meta", {}).get("ASSIGNER")

    def parse_data_format(self):
        return self._source_data.get("cve", {}).get("data_format")

    def parse_references_list(self):
        result = []
        for ref in (
            self._source_data.get("cve", {}).get("references", {}).get("reference_data")
        ):
            tag_list = []
            for tag in ref.get("tags"):
                tag_name = tag.lower()
                tag_name = tag_name.replace(" ", "_")
                tag_list.append(tag_name)

            result.append(
                {
                    "name": ref["name"],
                    "url": ref["url"],
                    "refsource": ref.get("refsource"),
                    "tagList": tag_list,
                }
            )

        return result

    def parse_cpe_list(self):
        result = []
        for node in self._source_data.get("configurations", {}).get("nodes"):
            cpe_match_list = node.get("cpe_match")
            for cpe_match in cpe_match_list:
                result.append(
                    {
                        "uri": cpe_match["cpe23Uri"],
                        "isVulnerable": cpe_match["vulnerable"],
                    }
                )

        return result

    def parse_base_metric_v2(self):
        result = {}

        base_metric_v2: dict = self._source_data.get("impact", {}).get("baseMetricV2")
        if base_metric_v2:
            result["cvss_v2"] = {
                "vector": base_metric_v2.get("cvssV2", {}).get("vectorString"),
                "version": base_metric_v2["cvssV2"]["version"],
                "accessVector": base_metric_v2["cvssV2"]["accessVector"],
                "accessComplexity": base_metric_v2["cvssV2"]["accessComplexity"],
                "authentication": base_metric_v2["cvssV2"]["authentication"],
                "confidentialityImpact": base_metric_v2["cvssV2"][
                    "confidentialityImpact"
                ],
                "integrityImpact": base_metric_v2["cvssV2"]["integrityImpact"],
                "availabilityImpact": base_metric_v2["cvssV2"]["availabilityImpact"],
                "baseScore": base_metric_v2["cvssV2"]["baseScore"],
            }

            result["severity"] = base_metric_v2["severity"]
            result["exploitabilityScore"] = base_metric_v2["exploitabilityScore"]
            result["impactScore"] = base_metric_v2["impactScore"]
            result["isObtainAllPrivilege"] = base_metric_v2["obtainAllPrivilege"]
            result["isObtainUserPrivilege"] = base_metric_v2["obtainUserPrivilege"]

            result["isObtainOtherPrivilege"] = base_metric_v2["obtainOtherPrivilege"]

            # CVE-2016-0099 nie ma UserInteractionRequired
            result["isUserInteractionRequired"] = base_metric_v2.get(
                "userInteractionRequired", None
            )

        return result

    def parse_base_metric_v3(self):
        result = {}

        base_metric_v3: dict = self._source_data.get("impact", {}).get("baseMetricV3")
        if base_metric_v3:
            result["cvss_v3"] = {
                "vector": base_metric_v3.get("cvssV3", {}).get("vectorString"),
                "version": base_metric_v3["cvssV3"]["version"],
                "attackVector": base_metric_v3["cvssV3"]["attackVector"],
                "attackComplexity": base_metric_v3["cvssV3"]["attackComplexity"],
                "privilegesRequired": base_metric_v3["cvssV3"]["privilegesRequired"],
                "userInteraction": base_metric_v3["cvssV3"]["privilegesRequired"],
                "scope": base_metric_v3["cvssV3"]["scope"],
                "confidentialityImpact": base_metric_v3["cvssV3"][
                    "confidentialityImpact"
                ],
                "integrityImpact": base_metric_v3["cvssV3"]["integrityImpact"],
                "availabilityImpact": base_metric_v3["cvssV3"]["availabilityImpact"],
                "baseScore": base_metric_v3["cvssV3"]["baseScore"],
                "baseSeverity": base_metric_v3["cvssV3"]["baseSeverity"],
            }
            result["exploitabilityScore"] = base_metric_v3["exploitabilityScore"]
            result["impactScore"] = base_metric_v3["impactScore"]

        return result


class CVESimplifier:
    def __init__(self, current_working_dir: str, src_filepath_list: list[str]) -> None:
        self.cve_simplified_filepath = FileMager.get_cve_simplified_filepath(
            current_working_dir
        )
        self.cve_list = self.get_simplified_cves(src_filepath_list)

        with open(self.cve_simplified_filepath, "w", encoding="utf-8") as f:
            json.dump(self.cve_list, f, indent=4)

    def get_simplified_cves(self, src_filepath_list: list[str]) -> list[str]:
        output_data_list = []

        for filepath in src_filepath_list:
            # 1. odczytuję plik json z podatnosciami CVE
            with open(filepath, "r") as f:
                data = json.loads(f.read())

            # licznik do sztucznego id
            artifical_id = 1  # needed for dummy data in JS
            for cve in data.get("CVE_Items"):
                # parsowanie kazego CVE
                parsed_data = CVEParser(data=cve, artifical_id=artifical_id).data

                artifical_id += 1
                output_data_list.append(parsed_data)

        return output_data_list
