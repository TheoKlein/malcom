import md5

import requests
from Malcom.feeds.core import Feed
import Malcom.auxiliary.toolbox as toolbox
from Malcom.model.datatypes import Ip


class TorExitNodes(Feed):
    """
    This gets data from https://www.dan.me.uk/tornodes
    """
    def __init__(self):
        super(TorExitNodes, self).__init__(run_every="1h")
        self.source = "https://www.dan.me.uk/tornodes"
        self.description = "List of Tor exit nodes"

    def update(self):
        feed = requests.get(self.source, verify=False)

        if feed.status_code != 200:
            self.status = feed.text
            return False

        feed = feed.text
        if feed.find('Umm... You can only fetch the data every 30 minutes'):
            self.status = "Burn out. Can only fetch the data every 30 minutes."
            return False

        start = feed.find('<!-- __BEGIN_TOR_NODE_LIST__ //-->') + len('<!-- __BEGIN_TOR_NODE_LIST__ //-->')
        end = feed.find('<!-- __END_TOR_NODE_LIST__ //-->')

        feed = feed[start:end].replace('\n', '').replace('<br />', '\n').replace('&gt;', '>').replace('&lt;', '<').split('\n')

        for line in feed:
            self.analyze(line)
        return True

    def analyze(self, line):

        fields = line.split('|')

        if len(fields) < 8:
            return

        ip = toolbox.find_ips(fields[0])[0]
        ip = Ip(ip=ip, tags=['tor'])

        tornode = {}
        tornode['description'] = "Tor exit node"
        tornode['ip'] = fields[0]
        tornode['name'] = fields[1]
        tornode['router-port'] = fields[2]
        tornode['directory-port'] = fields[3]
        tornode['flags'] = fields[4]
        tornode['uptime'] = fields[5]
        tornode['version'] = fields[6]
        tornode['contactinfo'] = fields[7]

        tornode['id'] = md5.new(tornode['ip']+tornode['name']).hexdigest()

        tornode['value'] = "Tor node: %s (%s)" % (tornode['name'], tornode['ip'])
        tornode['source'] = self.name

        ip.add_evil(tornode)
        ip.seen()
        self.commit_to_db(ip)
