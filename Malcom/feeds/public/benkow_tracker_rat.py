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


class BenkowTrackerRat(Feed):

    def __init__(self):
        super(BenkowTrackerRat, self).__init__(run_every="1h")
        self.description = "This feed contains known Malware C2 servers"
        self.source = "http://benkow.cc/export_rat.php"

    def update(self):
        res = requests.get(self.source, verify=False)
        
        if res.status_code != 200:
            self.status = res.text
            return False
        file = StringIO(res.text)
        next(file, None)
        reader = csv.reader(file, delimiter=';')
        for data in reader:
            self.analyze({
                'url': data[2],
                'ip': data[3],
                'first_seen': data[4],
                'mal_type': data[1]
            })
        return True

    def analyze(self, dict):
        evil = dict

        evil['date_added'] = datetime.datetime.strptime(dict['first_seen'], "%d-%m-%Y")

        # url
        evil['url'] = dict['url']
        evil['id'] = md5.new(evil['url'] + dict['first_seen']).hexdigest()
        evil['description'] = self.description
        evil['source'] = self.name

        url = Url(url=evil['url'], tags=[dict['mal_type']])

        url.seen(first=evil['date_added'])
        url.add_evil(evil)
        self.commit_to_db(url)

        # ip
        evil['url'] = dict['ip']
        evil['id'] = md5.new(evil['url'] + dict['first_seen']).hexdigest()

        ip = Ip(ip=dict['ip'], tags=[dict['mal_type']])
        ip.seen(first=evil['date_added'])
        ip.add_evil(evil)
        self.commit_to_db(ip)