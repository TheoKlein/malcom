import requests
import md5

from Malcom.model.datatypes import Ip
from Malcom.feeds.core import Feed

from bs4 import BeautifulSoup


class Alienvault(Feed):

    def __init__(self):
        super(Alienvault, self).__init__(run_every="1h")

        self.source = "http://reputation.alienvault.com/reputation.data"
        self.description = "Alienvault IP Reputation"

    def update(self):
        res = requests.get(self.source, verify=False)
        if res.status_code != 200:
            self.status = res.text
            return False

        lines = res.text.split('\n')
        for line in lines:
            self.analyze({
                'ip': line.split('#')[0],
                'score': line.split('#')[2]
            })
        return True

    def analyze(self, dict):
        evil = dict

        evil['host'] = dict['ip']
        evil['id'] = md5.new(evil['ip'] + evil['score'] + '/7').hexdigest()
        evil['description'] = 'Threat Score %s/7 by Alienvault.com' % dict['score'] 
        evil['source'] = self.name

        ip = Ip(ip=evil['host'])

        ip.seen()
        ip.add_evil(evil)
        self.commit_to_db(ip)