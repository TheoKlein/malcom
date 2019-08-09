import datetime
import re
import md5
import requests
from StringIO import StringIO

import Malcom.auxiliary.toolbox as toolbox
from Malcom.model.datatypes import Ip, Hostname
from Malcom.feeds.core import Feed


class FeodoTracker(Feed):

    descriptions = {
        'Cridex': "also known as Bugat was an ebanking Trojan active until around 2013. This variant is not active anymore.",
        'Feodo': "is a successor of the Cridex ebanking Trojan that first appeared in 2010. This variant is not active anymore.",
        'Geodo': "is a successor of the Feodo ebanking Trojan that first appeared in 2014. This variant is commonly also known as Emotet. This variant is not active anymore.",
        'Dridex': "is a successor of the Cridex ebanking Trojan. It first appeared in 2011 and is still very active as of today (2018). There are speculations that the botnet masters behind the ebanking Trojan Dyre moved their operation over to Dridex.",
        "Heodo": "is a successor of the Geodo (aka Emotet). It first appeared in March 2017 and is also commonly known as Emotet. While it was initally used to commit ebanking fraud, it later turned over to a Pay-Per-Install (PPI)-like botnet which is propagating itself through compromised email credentials.",
        "TrickBot": "has no code base with Emotet. However, TrickBot usually gets dropped by Emotet for lateral movement and to drop additional malware (such as Ryuk ransomware)."
    }

    def __init__(self):
        super(FeodoTracker, self).__init__()
        self.source = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
        self.description = "Feodo Tracker RSS Feed."

    def update(self):
        r = requests.get(self.source, verify=False)
        f = r.text.replace('\r', '').split('\n')
        for line in f[9:-1]:
            first_seen, dst_ip, _, last_online, malware = line.split(',')
            self.analyze({
                'first_seen': first_seen,
                'dst_ip': dst_ip,
                'last_online': last_online,
                'malware': malware
            })

    def analyze(self, dict):
        evil = dict

        try:
            evil['date_added'] = datetime.datetime.strptime(dict['first_seen'], "%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass

        evil['host'] = dict['dst_ip']
        evil['version'] = dict['malware']
        evil['description'] = FeodoTracker.descriptions[dict['malware']]
        evil['id'] = md5.new(evil['host'] + evil['description']).hexdigest()
        evil['source'] = self.name

        if toolbox.is_ip(evil['host']):
            elt = Ip(ip=evil['host'], tags=[dict['malware']])
        elif toolbox.is_hostname(evil['host']):
            elt = Hostname(hostname=evil['host'], tags=[dict['malware']])

        elt.seen(first=evil['date_added'])
        elt.add_evil(evil)
        self.commit_to_db(elt)
