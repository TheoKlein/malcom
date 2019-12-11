FROM ubuntu:18.04
MAINTAINER Thomas Chopitea <tomchop@gmail.com>

# update and install dependencies
RUN apt-get -qq update && apt-get -qqy install build-essential git python-dev libevent-dev mongodb libxml2-dev libxslt-dev zlib1g-dev redis-server libffi-dev libssl-dev python-pip

# VOLUME ['/var/lib/mongodb']
# scapy
ADD https://github.com/secdev/scapy/archive/v2.1.0.tar.gz /opt/scapy-v2.1.0.tar.gz
RUN cd /opt && \
	tar xzf scapy-v2.1.0.tar.gz && \
	rm scapy-v2.1.0.tar.gz && \
	mv scapy* scapy && \
	cd scapy && \
	python setup.py install

COPY ./requirements.txt /opt/malcom/requirements.txt

# set working dir, install python modules and launch webserver
WORKDIR /opt/malcom

# get maxmind geoip database
ADD http://geolite.maxmind.com/download/geoip/database/GeoLite2-City.mmdb.gz /opt/malcom/Malcom/auxiliary/geoIP/GeoLite2-City.mmdb.gz
RUN cd /opt/malcom/Malcom/auxiliary/geoIP && \
	gunzip -d GeoLite2-City.mmdb.gz && \
	mv GeoLite2-City.mmdb GeoIP2-City.mmdb
RUN pip install -r requirements.txt

COPY ./ /opt/malcom

RUN cp malcom.conf.example malcom.conf && \
    echo service mongodb start > start.sh && \
    echo service redis-server start >> start.sh && \
    echo ./malcom.py -c malcom.conf >> start.sh && \
    chmod +x start.sh
CMD ./start.sh

