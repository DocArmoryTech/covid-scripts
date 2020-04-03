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

bazaar_url="https://mb-api.abuse.ch/api/v1/"
bazaar_query={'query':'get_taginfo', 'tag':'COVID-19'}

API_REF_CONTEXTS=['dropped_by_sha256','dropping_sha256']
API_LINK_CONTEXTS=['urlhaus','any_run','joe_sandbox','malpedia','twitter','links']

def genFileObj(sample):
    sampl = GenericObjectGenerator('file')
    sampl.add_attribute("md5", value=sample['md5_hash'], to_ids=True)
    sampl.add_attribute("filename", value=sample['file_name'], to_ids=False, disable_correlation=True)
    sampl.add_attribute("sha1", value=sample['sha1_hash'], to_ids=True)
    sampl.add_attribute("sha256", value=sample['sha256_hash'], to_ids=True)
    sampl.add_attribute("ssdeep", value=sample['ssdeep'], to_ids=True)
    sampl.add_attribute("size-in-bytes", value=sample['file_size'], to_ids=False, disable_correlation=True)
    sampl.add_attribute("state", value="Malicious", to_ids=False, disable_correlation=True)
    sampl.add_attribute("mimetype", value=sample['file_type_mime'].replace('\\',''), to_ids=False, disable_correlation=True)

    return sampl

def getSampleDetail(sha256_hash):
    details_query={'query':'get_info', 'hash':'{}'.format(sha256_hash)}
    details_request=requests.post(bazaar_url, data=details_query)

    print("detailing {} ...".format(sha256_hash))
    samp_details=json.loads(details_request.text)
    return samp_details.get('data')[0] if (samp_details.get('query_status') == 'ok') else None

# a dict of samples to add to the Event, keyed with <k>sha256 containing <v>MISP-Object Files
samples={}
# a dict of samples already in the Event, keyed with <k>sha256 containing <v>MISP-Object Files
existing_samples={}

# a cache of all the attributes to be added to the event
attributes = {}

#misp setup
pm = PyMISP(misp_url, misp_key)
misp_event=MISPEvent()
search=pm.search(controller='events', eventinfo=misp_event_name)

if ( len(search) == 1):
    misp_event.load(search[0])

    #load 'existing_samples' dictionary from misp_event
    for obj in misp_event.get('Object'):
        if (obj.name == "file"):
            existing_samples.update({obj.get('sha256') : obj})

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
    if (hash_id not in existing_samples):
        sample_object=genFileObj(sample)
        samples.update({hash_id : sample_object})

# iterate through the list of samples
#   - a copy of the 'samples' so that we can updating the
#     dictionary while iterating through it; this allows for
#     one level of sample crawling. i.e. all samples refered
#     to by sampled tagged COVID-19 will be included in the Event
for hash,sample in samples.copy().items():

    # get a detailed report of the sample
    details = getSampleDetail(hash)
    if (details is not None):
        # if it exists, add the comment
        if ( 'comment' in details ):
            comment=details['comment']
            if ( comment is not None ):
                newattr = MISPAttribute()
                newattr.category = commattr['category']
                newattr.type = commattr['type']
                newattr.value = commattr['value']
                newattr.to_ids = commattr['to_ids']
                sample.add_reference(referenced_uuid=newattr.uuid, relationship_type='related-to')
                attributes.update({newattr.value : newattr})

        # find and add x-references
        if ( 'file_information' in details):
            info=details['file_information']

            if (info is not None):
                for context_set in info:
                    context=context_set['context']
                    value=context_set['value']

                    print("context: {}, value: {}".format(context, value))

                    if ( context in API_REF_CONTEXTS ):
                        ref_uuid=""

                        # if referenced sample is not already represented, create it and add to samples<dict>
                        if ( value not in samples ):
                            refSamp=getSampleDetail(value)
                            if (refSamp is not None):
                                refSampFile = genFileObj(refSamp)
                                samples.update({value : refSampFile})

                        if ( value in samples ):
                            ref_uuid=samples[value].uuid

                            if (context == "dropped_by_sha256"):
                                sample.add_reference(referenced_uuid=ref_uuid, relationship_type='dropped-by')
                            else:
                                sample.add_reference(referenced_uuid=ref_uuid, relationship_type='drops')
                    elif ( context.casefold() in API_LINK_CONTEXTS ):
                        url_ref=value.replace('\\','')
                        attribute = MISPAttribute()
                        if ( url_ref not in attributes):
                            attribute.category = "External analysis"
                            attribute.type = "url"
                            attribute.value = url_ref
                            attribute.to_ids = False
                            attribute.disable_correlation = True
                            attributes.update({attribute.value : attribute})
                        else:
                            attribute=attributes[url_ref]

                        sample.add_reference(referenced_uuid=attribute.uuid, relationship_type='related-to')
                    else:
                        print("Lost context: {}".format(context))

        attribute = MISPAttribute()
        attribute.category = "External analysis"
        attribute.type = "url"
        attribute.value = "https://bazaar.abuse.ch/sample/{}/".format(hash)
        attribute.to_ids = False
        attribute.disable_correlation = True
        attributes.update({attribute.value : attribute})
        sample.add_reference(referenced_uuid=attribute.uuid, relationship_type='derived-from')

for value,attribute in attributes.items():
    pm.add_attribute(misp_event, attribute)

for hash,sample in samples.items():
    misp_event.add_object(sample)


event=pm.update_event(misp_event)
