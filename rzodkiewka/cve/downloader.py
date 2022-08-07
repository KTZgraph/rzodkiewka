from bs4 import BeautifulSoup
import requests
import os
import zipfile

from helpers.feed_manager import FeedManager
from helpers.file_manager import FileMager


class CVEDownloader:
    def __init__(self, current_working_dir: str) -> None:
        self.feed_url = FeedManager.CVE_FEED_URL
        self.base_url = FeedManager.CVE_BASE_URL
        self.output_dirpath = FileMager.get_cve_output_dirpath(current_working_dir)

        if not os.path.isdir(self.output_dirpath):
            os.mkdir(self.output_dirpath)

        source_file_links = self.scrape_file_links(self.feed_url, self.base_url)
        self.filepaths = self.download(source_file_links)

    def scrape_file_links(self, URL: str, BASE_URL: str) -> list[str]:
        """Pobiera listę linków do plików zip zawierających podatnośći CVE"""
        source = requests.get(URL).text
        soup = BeautifulSoup(source, "html.parser")
        # tylko jedna tabela w sordku diva o id "divJSONF eeds"
        soup = soup.find("div", {"id": "divJSONFeeds"})
        soup = soup.find("table")

        files_urls = []
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if href.split(".")[-1] == "zip":
                files_urls.append(f"{BASE_URL}{href}")

        return files_urls

    def download(self, source_links: list[str]) -> list[str]:
        """Pobiera i zapisuje pliki w formacie zip
        1. pobiera wszystki pliki zip,
        2. zapisuje zipy
        3. rozpakowuje zipy i zapisuje rozpakowane plik
        4. usuwa zipy
        5. zwraca listę ścieżek rozpakowanych zipów
        """
        filename_list = []
        for link in source_links:
            zip_filename = link.split("/")[-1]
            zip_filepath = os.path.join(self.output_dirpath, zip_filename)

            data = requests.get(link)
            # zapisanie zipa
            with open(zip_filepath, "wb") as f:
                f.write(data.content)

            # rozpakowywanie zipa
            with zipfile.ZipFile(zip_filepath, "r") as zip_ref:
                # tylko jeden plik
                extracted_file_name = zip_ref.namelist()[0]
                zip_ref.extractall(self.output_dirpath)

            # usuwanie zipa
            os.remove(zip_filepath)

            # dodanie ścieżki rozpakowanego pliku do listy
            filename_list.append(extracted_file_name)

        return filename_list
