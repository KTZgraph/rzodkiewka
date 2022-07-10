import os
from typing import Optional
from ..helpers import utils

class CVEList:
    CVE_FILEPATH = "cve.json"
    def __init__(self, source_filepath_list:list[str], output_filepath:Optional[str]=None) -> None:
        self.source_filepath_list = source_filepath_list
        self._cve_list = self.get_cve_list()
        self._cve_filepath = self.save_cves(output_filepath)
    
    @property
    def cve_list(self):
        return self._cve_list

    @property
    def cve_filepath(self):
        return self._cve_filepath 

    def get_cve_list(self)->list[dict]:
        """Return list with all cves dicts"""
        
        result = []
        for source_filepath in self.source_filepath_list:
            data = utils.get_dict_from_json_file(source_filepath)
            result.extend(data)

            # remove simplified source files
            os.remove(source_filepath)

        # return list of cves dicts
        return result
    
    def save_cves(self, output_filepath:Optional[str]=None):
        if output_filepath:
            utils.save_dict_as_json(self._cve_list, output_filepath)
            return output_filepath
        
        utils.save_dict_as_json(self._cve_list, CVEList.CVE_FILEPATH)
        return CVEList.CVE_FILEPATH