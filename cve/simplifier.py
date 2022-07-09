import os
from helpers import utils

class CVEParser:
    def __init__(self, data) -> None:
        self._source_data = data
        _, cwe_id = self.parse_problemtype_data()
        cve_id, published, modified, description_data = self.parse_metadata()
        self._result = {
            "cwe_id": cwe_id,
            "description": description_data,
            "cve_id": cve_id,
            "published": published,
            "modified": modified,
            "version": self.parse_version(),
            "assigner": self.parse_assigner(),
            "data_format": self.parse_data_format(),
            "references_list": self.parse_references_list(),
            "cpe_list": self.parse_cpe_list(),
            "base_metric_v2": self.parse_base_metric_v2(),
            "base_metric_v3": self.parse_base_metric_v3(),
        }

    @property
    def data(self)->dict:
        return self._result

    def parse_problemtype_data(self):
        for problemtype_data in self._source_data.get('cve').get('problemtype').get('problemtype_data'):
            description = problemtype_data['description']
            cwe_id =  description[0].get('value') if description else None

        return description, cwe_id

    def parse_metadata(self):
        cve_id=self._source_data['cve']['CVE_data_meta']['ID']
        published = self._source_data['publishedDate']
        modified=self._source_data['lastModifiedDate']
        description_data= self._source_data['cve']['description']['description_data'][0]['value']
        return cve_id, published, modified, description_data

    def parse_version(self):
        return self._source_data.get('cve', {}).get('data_version')

    def parse_assigner(self):
        return self._source_data.get('cve', {}).get('CVE_data_meta', {}).get('ASSIGNER')

    def parse_data_format(self):
        return self._source_data.get('cve', {}).get('data_format')
    
    def parse_references_list(self):
        result = []
        for ref in self._source_data.get('cve', {}).get('references', {}).get('reference_data'):
            tag_list = []
            for tag in ref.get('tags'):
                tag_name = tag.lower()
                tag_name = tag_name.replace(' ' ,'_')
                tag_list.append(tag_name)

            result.append({
                "name" : ref['name'],
                "url": ref['url'],
                "refsource": ref.get('refsource'),
                "tags": tag_list
            })

        return result

    def parse_cpe_list(self):
        result = []
        for node in self._source_data.get('configurations', {}).get('nodes'):
            cpe_match_list= node.get('cpe_match')
            for cpe_match in cpe_match_list:
                result.append({
                    "uri": cpe_match['cpe23Uri'],
                    "is_vulnerable": cpe_match['vulnerable']
                })

        return result

    def parse_base_metric_v2(self):
        result = {}

        base_metric_v2:dict = self._source_data.get('impact', {}).get('baseMetricV2')
        if base_metric_v2:
            result["cvss_v2"] = {
                "vector": base_metric_v2.get('cvssV2', {}).get('vectorString'),
                "version": base_metric_v2['cvssV2']['version'],
                "access_vector": base_metric_v2['cvssV2']['accessVector'],
                "access_complexity": base_metric_v2['cvssV2']['accessComplexity'],
                "authentication": base_metric_v2['cvssV2']['authentication'],
                "confidentiality_impact": base_metric_v2['cvssV2']['confidentialityImpact'],
                "integrity_impact": base_metric_v2['cvssV2']['integrityImpact'],
                "availability_impact": base_metric_v2['cvssV2']['availabilityImpact'],
                "base_score": base_metric_v2['cvssV2']['baseScore']
            }

            result["severity"]=base_metric_v2['severity'],
            result["exploitability_score"]=base_metric_v2['exploitabilityScore'],
            result["impact_score"]=base_metric_v2['impactScore'],
            result["is_obtain_all_privilege"]=base_metric_v2['obtainAllPrivilege'],
            result["is_obtain_user_privilege"]=base_metric_v2['obtainUserPrivilege'],
            result["is_obtain_other_privilege"]=base_metric_v2['obtainOtherPrivilege'],
            # CVE-2016-0099 nie ma UserInteractionRequired
            result["is_user_interaction_required"]=base_metric_v2.get('userInteractionRequired', None),

        return result

    def parse_base_metric_v3(self):
        result = {}

        base_metric_v3:dict = self._source_data.get('impact', {}).get('baseMetricV3')
        if base_metric_v3:
            result["cvss_v3"] = {
                "vector": base_metric_v3.get('cvssV3', {}).get('vectorString'),
                "version":base_metric_v3['cvssV3']['version'],
                "attack_vector":base_metric_v3['cvssV3']['attackVector'],
                "attack_complexity":base_metric_v3['cvssV3']['attackComplexity'],
                "privileges_required":base_metric_v3['cvssV3']['privilegesRequired'],
                "user_interaction":base_metric_v3['cvssV3']['privilegesRequired'],
                "scope":base_metric_v3['cvssV3']['scope'],
                "confidentiality_impact":base_metric_v3['cvssV3']['confidentialityImpact'],
                "integrity_impact":base_metric_v3['cvssV3']['integrityImpact'],
                "availability_impact":base_metric_v3['cvssV3']['availabilityImpact'],
                "base_score":base_metric_v3['cvssV3']['baseScore'],
                "base_severity":base_metric_v3['cvssV3']['baseSeverity']
            }
            result["exploitability_score"]=base_metric_v3['exploitabilityScore']
            result["impact_score"]=base_metric_v3['impactScore']

        return result
            

class CVESimplifier:
    def __init__(self, cve_simplifier) -> None:
        self._source_filename_list = cve_simplifier.filename_list
        self.output_filepaths = self.save_simplified_cves()

    def save_simplified_cves(self):
        output_files = []

        for filename in self._source_filename_list:
            data = utils.get_dict_from_json_file(filename)
            
            result = []
            for cve in data.get('CVE_Items'):
                cve_parser = CVEParser(data=cve)
                result.append(cve_parser.data)
            
            result_filename = f"output\simplified-{filename}"
            utils.save_dict_as_json(data=result, filename=result_filename)
            
            #add oiutput files to the list
            output_files.append(result_filename)

            #remove source file
            os.remove(filename)

        return output_files