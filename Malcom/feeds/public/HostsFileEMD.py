import md5
import requests

from Malcom.feeds.core import Feed
from Malcom.model.datatypes import Url


class HostsFileEMD(Feed):

    def __init__(self):
        super(HostsFileEMD, self).__init__(run_every="1h")
        self.description = "Sites engaged in malware distribution."
        self.source = "https://hosts-file.net/emd.txt"

    def update(self):
        res = requests.get(self.source, verify=False)
        
        if res.status_code != 200:
            self.status = res.text
            return False
        lines = res.text.split('\n')[9:]
        for line in lines:
            if "127.0.0.1\t" in line:
                data = line.replace('127.0.0.1\t', '').replace('\n', '')
                self.analyze({
                    'url': data
                })

        return True

    def analyze(self, dict):
        evil = dict

        evil['url'] = dict['url']
        evil['id'] = md5.new(evil['url'] + 'HostsFileEMD').hexdigest()
        evil['description'] = self.description
        evil['source'] = self.name

        url = Url(url=evil['url'])
        url.seen()
        url.add_evil(evil)
        self.commit_to_db(url)