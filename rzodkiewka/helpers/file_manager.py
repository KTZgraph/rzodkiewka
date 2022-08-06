import os


class FileMager:
    CWE_FILENAME = "cwe.json"
    CWE_OUTPUT_DIR_NAME = "output_cwe"
    CWE_OUTPUT_FILENAME_NAME = "cwe.json"
    CVE_OUTPUT_DIR_NAME = "output_cve"

    @staticmethod
    def get_cve_output_filename(cwe_code: str) -> str:
        return f"{cwe_code}.json"

    @staticmethod
    def get_cve_filepath(current_working_dir: str, cwe_code: str) -> str:
        return os.path.join(
            current_working_dir, FileMager.CVE_OUTPUT_DIR_NAME, cwe_code
        )

    @staticmethod
    def get_cwe_output_dir(current_working_dir: str) -> str:
        return os.path.join(current_working_dir, FileMager.CWE_OUTPUT_DIR_NAME)

    @staticmethod
    def get_cwe_output_filepath(current_working_dir: str) -> str:
        return os.path.join(
            current_working_dir,
            FileMager.CWE_OUTPUT_DIR_NAME,
            FileMager.CWE_OUTPUT_FILENAME_NAME,
        )
