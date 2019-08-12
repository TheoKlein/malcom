# -*- coding: utf-8 -*-
import csv
import md5
import requests
import datetime

from StringIO import StringIO
from Malcom.feeds.core import Feed
from Malcom.model.datatypes import Url, Ip

import sys
reload(sys)
sys.setdefaultencoding('utf-8')


class RansomwareTracker(Feed):

    def __init__(self):
        super(RansomwareTracker, self).__init__(run_every="1h")
        self.description = "Ransomware Tracker offers various types of blocklists that allows you to block Ransomware botnet C&C traffic."
        self.source = "http://ransomwaretracker.abuse.ch/feeds/csv/"

    def update(self):
        res = requests.get(self.source, verify=False)
        
        if res.status_code != 200:
            self.status = res.text
            return False
        file = StringIO(res.text)
        for _ in range(9):
            next(file, None)
        reader = csv.reader(file, delimiter=',')
        for data in reader:
            try:
                self.analyze({
                    'url': data[4],
                    'ip': data[7],
                    'first_seen': data[0],
                    'malware': data[2]
                })
            except IndexError:
                pass
        return True

    def analyze(self, dict):
        evil = dict

        evil['date_added'] = datetime.datetime.strptime(dict['first_seen'], "%Y-%m-%d %H:%M:%S")

        # url
        evil['url'] = dict['url']
        evil['id'] = md5.new(evil['url'] + dict['first_seen']).hexdigest()
        evil['description'] = self.description
        evil['source'] = self.name

        url = Url(url=evil['url'], tags=[dict['malware']])

        url.seen(first=evil['date_added'])
        url.add_evil(evil)
        self.commit_to_db(url)

        # ip
        evil['url'] = dict['ip']
        evil['id'] = md5.new(evil['url'] + dict['first_seen']).hexdigest()

        ip = Ip(ip=dict['ip'], tags=[dict['malware']])
        ip.seen(first=evil['date_added'])
        ip.add_evil(evil)
        self.commit_to_db(ip)