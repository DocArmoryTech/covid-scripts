# covid-scripts
A collection of python scripts to push covid-themed threat intel into MISP

bazaartomisp.py
- downloads a summary of all samples tagged "COVID-19" from bazaar
- downloads details of each sample, as well as the samples refered to therein
- populates a misp-event with File objects represent the samples
- file-object relationships "dropped_by_sha256" and "dropping_sha256" are represented as relationships between files
- each file-object additionally references
   - the bazaar URL of the sample 
   - any URLs that feature as 3rd-party references to a sample (e.g. urlhaus)
- subsequent script runs update the event, but not the existing File-objects/samples, references or attributes 

domaintoolstomisp.py
- pulls domaintools' "covid-19-threat-list", 
- populates one event for each day with Attributes of type domain. 
- MISP Taxonomy [ifx-vetting](https://github.com/MISP/misp-taxonomies/blob/master/ifx-vetting/machinetag.json) is used to tag each domain with domaintools "score".

Subsequent runs of the script seek to update all events/days... takes a while, unless you specify a date filter (-d) as an argument
