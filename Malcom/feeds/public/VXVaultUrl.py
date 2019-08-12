import md5
import requests

from Malcom.feeds.core import Feed
from Malcom.model.datatypes import Url


class VXVaultUrl(Feed):

    def __init__(self):
        super(VXVaultUrl, self).__init__(run_every="1h")
        self.description = "VXVault Community URL list."
        self.source = "http://vxvault.net/URL_List.php"

    def update(self):
        res = requests.get(self.source, verify=False)
        
        if res.status_code != 200:
            self.status = res.text
            return False
        lines = res.text.split('\n')[3:]
        for line in lines:
            self.analyze({
                'url': line
            })

        return True

    def analyze(self, dict):
        evil = dict

        evil['url'] = dict['url']
        evil['id'] = md5.new(evil['url'] + 'VXVaultUrl').hexdigest()
        evil['description'] = self.description
        evil['source'] = self.name

        url = Url(url=evil['url'])
        url.seen()
        url.add_evil(evil)
        self.commit_to_db(url)