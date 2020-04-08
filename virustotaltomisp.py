#!/usr/bin/python3

import vt
import requests
from pymisp import PyMISP, MISPEvent
from pymisp.tools import GenericObjectGenerator
from pymisp.exceptions import InvalidMISPObject
import datetime
import argparse
import json
from urllib.parse import urlsplit

misp_url="https://misp.something.else/" ################## YOUR MISP URL
misp_key="your-api-key-goes-here"       ################## YOUR MISP API KEY
api_key="your-vt-api-key"               ################## YOUR VT API KEY (requires access to VT-Intelligence for search)


def getFileDetail(apikey: str, resource: str):
    url = "https://www.virustotal.com/vtapi/v2/file/report"
    params = {"apikey": apikey, "resource": resource, "allinfo": 'true'}
    # for now assume we're using a public API key - we'll figure out private keys later

    report = requests.get(url, params=params)
    report_json = report.json()
    if report_json["response_code"] == 1:
        return report_json
    else:
        error_msg = "{}: {}".format(resource, report_json["verbose_msg"])
        raise InvalidMISPObject(error_msg)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Pull reports and sample details from VirusTotal that match the hardcoded covid-themed query')
    parser.add_argument("-d", "--date", default="2020-03-17", required=False, help="Ignore entries before this date")
    args = parser.parse_args()

    client = vt.Client(api_key)
    query_strings=[
                   'positives:5+', 'AND',
                   'comment_author:thor', 'AND',
                   '(',
                   'comment:"#spec_covid19_phish_hunting"', 'OR',
                   'comment:"#covid19"',
                   ')', 'AND'
                  ]

    query_strings.append("fs:{}+".format(args.date))

    it = client.iterator('/intelligence/search', params={'query':  " ".join(query_strings), 'descriptors_only':'True'}, batch_size=25, limit=10000)

    pm=PyMISP(misp_url, misp_key)
    misp_event_name="CTI League - Phishing attachments [{}]"

    for sample in it:
        raw_report=getFileDetail(apikey=api_key, resource=sample.id)

        scandate=datetime.datetime.strptime(raw_report["scan_date"], '%Y-%m-%d %H:%M:%S')

        me=MISPEvent()
        this_event_name=misp_event_name.format(scandate.strftime("%Y-%m-%d"))
        search=pm.search(controller='events', eventinfo=this_event_name)

        if ( len(search) == 1):
            me.load(search[0])
        else:
            me.info=this_event_name
            pm.add_event(me)

        vtreport = GenericObjectGenerator('virustotal-report')
        vtreport.add_attribute("last-submission", value=raw_report["scan_date"])
        vtreport.add_attribute("permalink", value=raw_report["permalink"])
        ratio = "{}/{}".format(raw_report["positives"], raw_report["total"])
        vtreport.add_attribute("detection-ratio", value=ratio)


        file_object = GenericObjectGenerator('file')
        file_object.add_attribute("md5", value=raw_report["md5"])
        file_object.add_attribute("sha1", value=raw_report["sha1"])
        file_object.add_attribute("sha256", value=raw_report["sha256"])
        file_object.add_attribute("ssdeep", value=raw_report["ssdeep"])
        file_object.add_attribute("authentihash", value=raw_report["authentihash"])
        file_object.add_attribute("size-in-bytes", value=raw_report["size"])

        if ("exiftool" in raw_report["additional_info"]):
            file_object.add_attribute("mimetype", value=raw_report["additional_info"]["exiftool"]["MIMEType"])

        for filename in raw_report["submission_names"]:
            file_object.add_attribute("filename", value=filename)

        file_object.add_attribute("state", value="Malicious", to_ids=False, disable_correlation=True)

        vtreport.add_reference(referenced_uuid=file_object.uuid, relationship_type="annotates")

        urls=[]
        for url in raw_report["ITW_urls"]:
            parsed = urlsplit(url)
            url_object = GenericObjectGenerator('url')
            url_object.add_attribute("url", value=parsed.geturl())
            url_object.add_attribute("host", value=parsed.hostname)
            url_object.add_attribute("scheme", value=parsed.scheme)
            url_object.add_attribute("port", value=parsed.port)
            file_object.add_reference(referenced_uuid=url_object.uuid, relationship_type="downloaded-from")
            me.add_object(url_object)

        me.add_object(file_object)
        me.add_object(vtreport)

        pm.update_event(me)

    # really annoying vt-py client close
    client.close()
