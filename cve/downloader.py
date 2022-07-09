import requests
from bs4 import BeautifulSoup
import os

from helpers import utils

class CVEDownloader:
    MAIN_URL  = "https://nvd.nist.gov/vuln/data-feeds#JSON_FEED"
    BASE_URL = "https://nvd.nist.gov/" 

    def __init__(self) -> None:
        file_urls = self.get_cve_file_urls(CVEDownloader.MAIN_URL, CVEDownloader.BASE_URL)
        self.filename_list = self.download_files(file_urls)

    def get_cve_file_urls(self, url:str, base_url:str)->list[str]:
        source = requests.get(url).text
        soup = BeautifulSoup(source, "html.parser")
        soup = soup.find("div", {"id": "divJSONFeeds"})
        soup = soup.find("table")  # tylko jedna tabela w sordku diva

        files_urls = []
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if href.split(".")[-1] == "zip":
                files_urls.append(f'{base_url}{href}')

        return files_urls

    def download_files(self, file_urls:list[str])->list[str]:
        filename_list = []
        for f_url in file_urls:
            zip_filename = f_url.split("/")[-1]
            utils.download_zip_file(URL=f_url, filename=zip_filename)
            extracted_file = utils.unzip_package(zip_filename)[0]
            
            # remove zip file
            os.remove(zip_filename)
            filename_list.append(extracted_file)

        return filename_list