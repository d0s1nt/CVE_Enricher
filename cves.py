import requests
import pandas as pd
import re
import json
import vulners
import urllib.request

cves = [line.upper().rstrip('\n') for line in open('cves.txt','r')]
cvss = []
exploitable = []
rfscores = []
cvelinks = []

vulnersapikey = ""
rfapikey = ''


def exploit_check(cve):
   try:
        vulners_api = vulners.Vulners(f'api_key={vulnersapikey}')
        cvevuln = vulners_api.searchExploit(f'"{cve}"')
        if cvevuln:
            exploitable.append("Yes")
        else:
            exploitable.append("No")
   except:
       exploitable.append('')

def cvss_check(cve):
    try:

        cveres = requests.get(f"https://cve.circl.lu/api/cve/{cve}")
        cvejson = cveres.json()
        cvss.append(cvejson['cvss'])
    except:
        cvss.append('')

def rf_check(cve):
    try:
        url = f'https://api.recordedfuture.com/v2/vulnerability/{cve}/riskscore'
        token = rfapikey
        headers = {'X-RFToken':token}
        rfres = requests.get(url, headers=headers)
        rfjson = rfres.json()
        rfscores.append(rfjson['data']['riskScore'])
    except:
        rfscores.append('')

for cve in cves:
   if cve:
       cvss_check(cve)
       exploit_check(cve)
       rf_check(cve)        

output = {'CVE':cves, 'CVSS':cvss, 'Exploitable':exploitable, 'RF Score':rfscores}
df = pd.DataFrame(output, columns=['CVE','CVSS','Exploitable','RF Score'])
df.to_excel(f"Enriched_CVEs.xlsx",index=False)
