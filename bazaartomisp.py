#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pymisp import PyMISP, MISPEvent, MISPAttribute, MISPObject
from pymisp.tools import GenericObjectGenerator
import requests
import csv
import json

misp_url="https://misp.something.else/" ################## YOUR MISP URL
misp_key="your-api-key-goes-here"       ################## YOUR API KEY

#
misp_event_name="COVID-19 - bazaar.abuse.ch ++"

misp_check_cert=True                    ################### Set to False to ignore certificate errors
                                        ################### Or a CA_BUNDLE in case of self signed certificate 
                                        ################### (the concatenation of all the *.crt of the chain)

bazaar_url="https://mb-api.abuse.ch/api/v1/"
bazaar_query={'query':'get_taginfo', 'tag':'COVID-19'}

API_REF_CONTEXTS=['dropped_by_sha256','dropping_sha256']
API_LINK_CONTEXTS=['urlhaus','any_run','joe_sandbox','malpedia','twitter','links']

def addSampleByHash(hashes, event):
    hash=""
    if ( type(hashes) is list):
        hash=hashes[0]
    elif ( type(hashes) is str):
        hash=hashes
        hashes=[hash]

    sample_json = _getSampleJson(hash)

    if (sample_json is None):
        return

    sampl = GenericObjectGenerator('file')

    sampl.add_attribute("md5", value=sample_json['md5_hash'], to_ids=True)
    sampl.add_attribute("filename", value=sample_json['file_name'], to_ids=False, disable_correlation=True)
    sampl.add_attribute("sha1", value=sample_json['sha1_hash'], to_ids=True)
    sampl.add_attribute("sha256", value=sample_json['sha256_hash'], to_ids=True)
    sampl.add_attribute("ssdeep", value=sample_json['ssdeep'], to_ids=True)
    sampl.add_attribute("size-in-bytes", value=sample_json['file_size'], to_ids=False, disable_correlation=True)
    sampl.add_attribute("state", value="Malicious", to_ids=False, disable_correlation=True)
    sampl.add_attribute("mimetype", value=sample_json['file_type_mime'].replace('\\',''), to_ids=False, disable_correlation=True)

    # if it exists, add the comment
    if ( 'comment' in sample_json ):
        comment=sample_json['comment']
        if ( comment is not None ) and (len(comment) > 0):
            commattrs=pm.freetext(event, comment)

            for commattr in commattrs:
               if (commattr['value'] in attributes):
                   attr=attributes[commattr['value']]
                   sampl.add_reference(referenced_uuid=attr.uuid, relationship_type='related-to')
               else:
                   attr=event.add_attribute(commattr['type'], commattr['value'])
                   attributes.update({commattr['value']:attr})
                   sampl.add_reference(referenced_uuid=attr.uuid, relationship_type='related-to')

    # find and add x-references
    if ( 'file_information' in sample_json):
            info=sample_json['file_information']
            if (info is not None):
                for context_set in info:
                    context=context_set['context']
                    value=context_set['value']
                    print("context: {}, value: {}".format(context, value))
                    if ( context in API_REF_CONTEXTS ):
                        ref_uuid=""

                        addedSample=None
                        # if referenced sample is not already represented, recursively create it and add to the event and to samples<dict>
                        if (( value not in samples ) and (value not in hashes) ) :
                            addedSample=addSampleByHash([value]+hashes, event)

                        if (addedSample is not None):
                            ref_uuid=samples[value].uuid

                            if (context == "dropped_by_sha256"):
                                sampl.add_reference(referenced_uuid=ref_uuid, relationship_type='dropped-by')
                            else:
                                sampl.add_reference(referenced_uuid=ref_uuid, relationship_type='drops')
                    elif ( context.casefold() in API_LINK_CONTEXTS ):
                        url_ref=value.replace('\\','')
                        attribute = None
                        if ( url_ref not in attributes):
                            attribute = event.add_attribute('url', url_ref, to_ids=False, disable_correlation=True)
                            attributes.update({attribute.value : attribute})
                            sampl.add_reference(referenced_uuid=attribute.uuid, relationship_type='related-to')
                        else:
                            sampl.add_reference(referenced_uuid=attributes[url_ref].uuid, relationship_type='related-to')
                    else:
                        print("Lost context: {}".format(context))

    attribute = None
    report_url="https://bazaar.abuse.ch/sample/{}/".format(hash)
    if (report_url not in attributes):
        attribute = event.add_attribute("url", "https://bazaar.abuse.ch/sample/{}/".format(hash), to_ids = False, disable_correlation=True)
        attributes.update({attribute.value : attribute})
    else:
        attribute=attributes[report_url]

    sampl.add_reference(referenced_uuid=attribute.uuid, relationship_type='derived-from')
    sampl=event.add_object(sampl)
    samples.update({hash:sampl})
    return sampl


def _getSampleJson(sha256_hash):
    details_query={'query':'get_info', 'hash':'{}'.format(sha256_hash)}
    details_request=requests.post(bazaar_url, data=details_query)

    print("detailing {} ...".format(sha256_hash))
    try:
        samp_details=json.loads(details_request.text)
        return samp_details.get('data')[0] if (samp_details.get('query_status') == 'ok') else None
    except:
        print(details_request.content)

    return None

# a dict of samples in the Event, keyed with <k>sha256 containing <v>MISP-Object Files
samples={}

# a cache of all the attributes in the event
attributes={}

#misp setup
pm = PyMISP(misp_url, misp_key, ssl=misp_check_cert)
misp_event=MISPEvent()
search=pm.search(controller='events', eventinfo=misp_event_name)

if ( len(search) == 1):
    misp_event.load(search[0])

    #load 'samples' dictionary from misp_event
    for obj in misp_event.get('Object'):
        if (obj.name == "file"):
            existing_hash = obj.get_attributes_by_relation("sha256")[0]['value']
            samples.update({existing_hash : obj})

    #reload 'attributes' dictionary from misp_event
    for attr in misp_event.get('Attribute'):
        attributes.update({attr.value : attr})
else:
    misp_event.info=misp_event_name
    pm.add_event(misp_event)

#bazaar setup
r = requests.post(bazaar_url, data=bazaar_query)
bazaardata = json.loads(r.text)

# add File objects/samples that don't currently exist
for sample in bazaardata.get('data'):
    hash_id=sample["sha256_hash"]
    if (hash_id not in samples):
        addSampleByHash(hash_id, misp_event)

pm.update_event(misp_event)
