import md5
import requests

from Malcom.feeds.core import Feed
from Malcom.model.datatypes import Hostname


class InfosecCertPaItFQDN(Feed):

    def __init__(self):
        super(InfosecCertPaItFQDN, self).__init__(run_every="1h")
        self.description = "Updated FQDN Feed of Infosec.cert-pa.it"
        self.source = "https://infosec.cert-pa.it/analyze/listdomains.txt"

    def update(self):
        res = requests.get(self.source, verify=False)
        
        if res.status_code != 200:
            self.status = res.text
            return False
        lines = res.text.split('\n')[9:]
        for line in lines:
            self.analyze({
                'domain': line
            })

        return True

    def analyze(self, dict):
        evil = dict

        evil['host'] = dict['domain']
        evil['id'] = md5.new(evil['domain'] + 'InfosecCertPaItFQDN').hexdigest()
        evil['description'] = self.description
        evil['source'] = self.name

        elt = Hostname(hostname=evil['host'])
        elt.seen()
        elt.add_evil(evil)
        self.commit_to_db(elt)