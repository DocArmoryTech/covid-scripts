#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import pycountry
import re
import json
import requests
import gzip
import argparse
from pymisp import PyMISP, MISPEvent, MISPAttribute, MISPObject
from pymisp.tools import GenericObjectGenerator
import datetime

misp_url="https://your.misp/" ################## YOUR MISP URL
misp_key=""       ################## YOUR API KEY
badpanda_url="https://[your-server-name]/public.php/webdav/uas.all.tlpred.json.gz"
badpanda_user="the-share-name"
badpanda_password=""
pm=PyMISP(misp_url, misp_key)

misp_event_name="Datasets from major cybercrime RDP shops - UAS"

if __name__ == '__main__':

        tags=["current-event:pandemic=\"covid-19\"", "COVID-19", "pandemic:covid-19=\"cyber\"", "tlp:amber", "workflow:state=\"ongoing\"", "false-positive:risk=\"low\""]
        events={}
        creds={}
        places={}
        cmfrt=0



        json_records=gzip.decompress(requests.get(badpanda_url, auth=(badpanda_user,badpanda_password), headers={'X-Requested-With': 'XMLHttpRequest'}).content).decode()

        for line in json_records.split('\n'):
            cmfrt+=1
            data=None
            try:
                data=json.loads(line)
            except:
                print("This line wouldn't parse as json")
                print(line)

            if (data is None):
                continue

            fseen=datetime.datetime.strptime(data["first_seen"]['$date'], '%Y-%m-%dT%H:%M:%S.%fZ')
            lseen=datetime.datetime.strptime(data["last_seen"]['$date'], '%Y-%m-%dT%H:%M:%S.%fZ')

            if (fseen.astimezone() > lseen.astimezone()):
                print("Something is wonky with the timestamps")
            else:
                this_event_name=misp_event_name+" - [{} {}]".format(fseen.strftime("%Y-%m-%d"),fseen.strftime("%p"))

                me=MISPEvent()
                if (this_event_name in events):
                    me=events[this_event_name]
                else:
                    me.info=this_event_name

                #Geolocation
                geo=None
                cc=data['geo_country']
                country=pycountry.countries.get(alpha_2=cc)
                if (country is not None):

                    if ( me.info+cc in places ):
                        geo=places[me.info+cc]
                    else:
                        geo=GenericObjectGenerator('geolocation')
                        geo.add_attribute("country", value=pycountry.countries.get(alpha_2=cc).name)
                        me.add_object(geo)
                        places.update({me.info+cc:geo})

                #x509
                xfive=None
                if ("issuer" in data) :
                    if (len(data["issuer"]) > 2) :
                        xfive = GenericObjectGenerator('x509')
                        xfive.add_attribute("issuer", value=data["issuer"], to_ids=True)
                        if ( len(data["subject"]) > 0) :
                            xfive.add_attribute("subject", value=data["subject"], to_ids=True)
                        xfive.first_seen=fseen
                        xfive.last_seen=lseen
                        xfive.add_reference(referenced_uuid=host.uuid, relationship_type='characterizes')

                        me.add_object(xfive)

                #credential
                useracc = None
                user=""
                if ( len(data["domain"]) > 1):
                    if (re.match("^[\?|\_|\-|\~]+$|no_domain", data["domain"])):
                        user=data["username"]
                    else:
                        user=data["domain"]+"\\"+data["username"]

                useracc = None
                if (len(user) >0):
                    useracc = GenericObjectGenerator('credential')
                    useracc.add_attribute("username", value=user, to_ids=True)
                    useracc.add_attribute("origin", value="bruteforce-scanning", to_ids=False)
                    useracc.add_attribute("format", value="clear", to_ids=False)

                if (useracc is not None):
                    me.add_object(useracc)
                    creds.update({me.info+user:useracc})

                #ip-port
                host = GenericObjectGenerator('ip-port')
                host.add_attribute("ip", value=data["ip"], to_ids=True)
                host.add_attribute("dst-port", value=data["port"], to_ids=True)

                if (len(data["rr"]) > 0):
                    host.add_attribute("hostname", value=data["rr"], to_ids=True)

                if (lseen.astimezone() > fseen.astimezone()):
                    host.first_seen=fseen
                    host.last_seen=lseen


                if (geo is not None):
                    host.add_reference(referenced_uuid=geo.uuid, relationship_type='located')

                if (useracc is not None):
                    useracc.add_reference(referenced_uuid=host.uuid, relationship_type='user-of')

                me.add_object(host)
                events.update({me.info:me})

            if (cmfrt % 5000 == 0):
                print("5000 more")


for event in events:
    me=events[event]
    for tag in tags:
        me.add_tag(tag)

    event_file = open("./{}".format(me.uuid),'w')
    event_file.write(me.to_json())
    try:
        pm.add_event(me)
    except:
        print("adding the event went wrong")
