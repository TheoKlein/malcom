import requests
import md5

from Malcom.model.datatypes import Ip
from Malcom.feeds.core import Feed

from bs4 import BeautifulSoup


class BadIPs(Feed):

    def __init__(self):
        super(BadIPs, self).__init__(run_every="1h")

        self.source = "https://www.badips.com/get/list/any/"
        self.description = "Bad IPs"

    def update(self):
        # get from Lv 3 ~ 5
        for lv in range(51, 54):
            res = requests.get(self.source + chr(lv), verify=False)
            if res.status_code != 200:
                self.status = res.text
                return False

            lines = res.text.split('\n')
            for line in lines:
                self.analyze({
                    'ip': line,
                    'lv': chr(lv)
                })
        return True

    def analyze(self, dict):
        evil = dict

        evil['host'] = dict['ip']
        evil['id'] = md5.new(evil['ip'] + 'Lv %s' % dict['lv']).hexdigest()
        evil['description'] = 'This IP was reported for ' + dict['lv'] + '/5 malicious activity'
        evil['source'] = self.name
        ip = Ip(ip=evil['host'])

        ip.add_evil(evil)
        self.commit_to_db(ip)