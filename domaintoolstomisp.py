#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pymisp import PyMISP, MISPEvent
from pymisp.tools import GenericObjectGenerator
import gzip
from requests import get
import csv
import io
import datetime 

import argparse

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Parse domaintools covid-19 threat-list')
    parser.add_argument("-d", "--date", required=False, help="Ignore entries after this date")
    args = parser.parse_args()



    misp_url="https://misp.something.else/" ################## YOUR MISP URL
    misp_key="your-api-key-goes-here"       ################## YOUR API KEY

    pm=PyMISP(misp_url, misp_key)

    domaintools_url="https://covid-19-threat-list.domaintools.com/dt-covid-19-threat-list.csv.gz"

    csvcontent=gzip.decompress(get(domaintools_url).content).decode()
    reader=csv.reader(csvcontent.split('\n'), delimiter='\t')

    events={}

    filterdate="";
    if (len(args.date) == 10):
        filterdate=datetime.datetime.strptime(args.date, '%Y-%m-%d')
    else:
        filterdate=datetime.datetime.strptime("2020-01-01", '%Y-%m-%d')


    for row in reader:
        if (len(row) == 3):
            dom, seen, score = row
            seendate=datetime.datetime.strptime(seen, '%Y-%m-%d')
            if (seendate >= filterdate):
                 curEvent=MISPEvent()


                 eventName = '[{}] - Domaintools +70 malscore'.format(seen)
                 if (eventName not in events) :
                     print("searching for: {}".format(eventName))
                     search=pm.search(controller='events', eventinfo=eventName)
                     if ( len(search) == 1):
                         curEvent.load(search[0])
                         events.update({eventName : curEvent})
                     elif ( len(search) == 0):
                         curEvent.info=eventName
                         pm.add_event(curEvent)
                         events.update({eventName : curEvent})
                 else:
                     curEvent=events[eventName]

                 curEvent=events[eventName]

                 attr=curEvent.add_attribute('domain', dom)
                 curEvent.add_attribute_tag("ifx-vetting:score=\"{}\"".format(score), attr.uuid)
                 curEvent.add_attribute_tag("tlp:white", attr.uuid)
                 curEvent.add_attribute_tag("pandemic:covid-19=\"cyber\"", attr.uuid)

                 if ( int(score) >= 95 ):
                     curEvent.add_attribute_tag("estimative-language:likelihood-probability=\"almost-certain\"", attr.uuid)
                 elif ( int(score) >= 80):
                     curEvent.add_attribute_tag("estimative-language:likelihood-probability=\"very-likely\"", attr.uuid)
                 else:
                     curEvent.add_attribute_tag("estimative-language:likelihood-probability=\"likely\"", attr.uuid)

                 events[eventName] = curEvent

    for neweventname in events:
        print(neweventname)
        newevent=events[neweventname]
        event_file = open("./{}".format(newevent.uuid),'w')
        event_file.write(newevent.to_json())
        try:
            pm.update_event(newevent)
        except:
            print("Failed event: {}, uuid: {}".format(neweventname, newevent.uuid))
