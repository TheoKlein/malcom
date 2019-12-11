import requests
import md5

from Malcom.model.datatypes import Url
from Malcom.feeds.core import Feed

from bs4 import BeautifulSoup


class Fumik0_Tracker(Feed):

    def __init__(self):
        super(Fumik0_Tracker, self).__init__(run_every="1h")

        self.source = "https://tracker.fumik0.com/api/get-urls"
        self.description = "Fumik0 Tracker"

    def update(self):
        res = requests.get(self.source, verify=False)
        if res.status_code != 200:
            self.status = res.text
            return False

        lines = res.text.replace('<pre>', '').replace('</pre>', '').split('</br>')
        for line in lines[9:]:
            if line:
                self.analyze({
                    'url': line,
                })
        return True

    def analyze(self, dict):
        evil = dict

        evil['url'] = dict['url']
        evil['id'] = md5.new('fumik0' + evil['url']).hexdigest()
        evil['description'] = 'Mark by tracker.fumik0.com'
        evil['source'] = self.name

        url = Url(url=evil['url'])

        url.seen()
        url.add_evil(evil)
        self.commit_to_db(url)