import md5
import requests
import datetime

from Malcom.feeds.core import Feed
from Malcom.model.datatypes import Ip


class IPSpamList(Feed):

    def __init__(self):
        super(IPSpamList, self).__init__(run_every="7h")
        self.description = "Service provided by NoVirusThanks that keeps track of malicious IP addresses engaged in hacking attempts, spam comments"
        self.source = "http://www.ipspamlist.com/public_feeds.csv"

    def update(self):
        res = requests.get(self.source, verify=False)
        
        if res.status_code != 200:
            self.status = res.text
            return False
        lines = res.text.split('\n')[10:-1]
        for line in lines:
            data = line.split(',')
            self.analyze({
                'ip': data[2],
                'first_seen': data[0],
                'last_seen': data[1],
                'category': data[3]
            })

        return True

    def analyze(self, dict):
        evil = dict

        evil['first_seen'] = datetime.datetime.strptime(dict['first_seen'], "%Y-%m-%d %H:%M:%S")
        evil['last_seen'] = datetime.datetime.strptime(dict['last_seen'], "%Y-%m-%d %H:%M:%S")

        evil['url'] = dict['ip']
        evil['id'] = md5.new(evil['url'] + dict['category']).hexdigest()
        evil['description'] = self.description
        evil['source'] = self.name

        ip = Ip(ip=evil['url'])
        ip.seen(first=evil['first_seen'], last=evil['last_seen'])
        ip.add_evil(evil)
        self.commit_to_db(ip)