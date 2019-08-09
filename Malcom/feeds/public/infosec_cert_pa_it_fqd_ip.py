import md5
import requests

from Malcom.feeds.core import Feed
from Malcom.model.datatypes import Ip


class InfosecCertPaItIP(Feed):

    def __init__(self):
        super(InfosecCertPaItIP, self).__init__(run_every="1h")
        self.description = "Updated IP Feed of Infosec.cert-pa.it"
        self.source = "https://infosec.cert-pa.it/analyze/listip.txt"

    def update(self):
        res = requests.get(self.source, verify=False)
        
        if res.status_code != 200:
            self.status = res.text
            return False
        lines = res.text.split('\n')[9:]
        for line in lines:
            self.analyze({
                'ip': line
            })

        return True

    def analyze(self, dict):
        evil = dict

        evil['host'] = dict['ip']
        evil['id'] = md5.new(evil['ip'] + 'InfosecCertPaItIP').hexdigest()
        evil['description'] = self.description
        evil['source'] = self.name

        ip = Ip(ip=evil['host'])
        ip.seen()
        ip.add_evil(evil)
        self.commit_to_db(ip)