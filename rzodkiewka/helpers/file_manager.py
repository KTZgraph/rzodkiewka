import os


class FileMager:
    CWE_FILENAME = "cwe.json"
    CWE_OUTPUT_DIR_NAME = "output_cwe"
    CWE_OUTPUT_FILENAME_NAME = "cwe.json"
    CVE_OUTPUT_FILENAME_NAME = "cve_simplified.json"
    CWE_SIMPLIFIED_OUTPUT_FILENAME_NAME = "cwe_simplified.json"
    CVE_OUTPUT_DIR_NAME = "output_cve"
    GENERAL_OUTPUT_DIRNAME = "output"

    @staticmethod
    def get_cve_output_dirpath(current_working_dir: str) -> str:
        dirpath = os.path.join(current_working_dir, FileMager.CVE_OUTPUT_DIR_NAME)
        if not os.path.isdir(dirpath):
            os.mkdir(dirpath)

        return os.path.join(current_working_dir, FileMager.CVE_OUTPUT_DIR_NAME)

    @staticmethod
    def get_cve_output_filename(cwe_code: str) -> str:
        return f"{cwe_code}.json"

    @staticmethod
    def get_cve_simplified_filepath(current_working_dir: str) -> str:
        dirpath = os.path.join(current_working_dir, FileMager.GENERAL_OUTPUT_DIRNAME)
        if not os.path.isdir(dirpath):
            os.mkdir(dirpath)

        return os.path.join(
            dirpath,
            FileMager.CVE_OUTPUT_FILENAME_NAME,
        )

    @staticmethod
    def get_cve_splitted_filepath(current_working_dir: str, cwe_code: str) -> str:
        dirpath = os.path.join(current_working_dir, FileMager.CVE_OUTPUT_DIR_NAME)
        if not os.path.isdir(dirpath):
            os.mkdir(dirpath)

        return os.path.join(dirpath, cwe_code)

    @staticmethod
    def get_cwe_output_dir(current_working_dir: str) -> str:
        dirpath = os.path.join(current_working_dir, FileMager.CWE_OUTPUT_DIR_NAME)
        if not os.path.isdir(dirpath):
            os.mkdir(dirpath)

        return dirpath

    @staticmethod
    def get_cwe_output_filepath(current_working_dir: str) -> str:
        dirpath = os.path.join(current_working_dir, FileMager.CWE_OUTPUT_DIR_NAME)
        if not os.path.isdir(dirpath):
            os.mkdir(dirpath)

        return os.path.join(dirpath, FileMager.CWE_OUTPUT_FILENAME_NAME)

    @staticmethod
    def get_cwe_simplified_output_filepath(current_working_dir: str) -> str:
        dirpath = os.path.join(current_working_dir, FileMager.GENERAL_OUTPUT_DIRNAME)
        if not os.path.isdir(dirpath):
            os.mkdir(dirpath)

        return os.path.join(dirpath, FileMager.CWE_SIMPLIFIED_OUTPUT_FILENAME_NAME)
