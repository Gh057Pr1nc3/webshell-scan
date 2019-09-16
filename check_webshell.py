import requests
import re
import sys
import json, urllib, urllib2, argparse, hashlib
import time

requests.packages.urllib3.disable_warnings()
if len(sys.argv)<=2:
    print "scan_url.py <log.csv> <domain>"
    sys.exit(1)

if (sys.version_info > (3, 0)):
    print('Python 3 detected')
    print('Run this script with Python 2.x !')
    sys.exit()


def request_url(link, domain):
    result=0
    code = 0
    link = link.replace("\\","/")
    while True:
        result =  link.find("/", result)
        if result == -1:
            break
        url = "https://"+domain+link[result:]
        try:
            r = requests.get(url =url,verify=False)
            code = r.status_code
            if code < 400:
                return str(code)+","+url
        except:
            code =0
        result +=1
    return str(code)+",NULL"

def scan_vt(md5, i):
    api = ['da0c17684c7b5b44b8896130ffa3ce3038f05d1906c6eac698d731eb685e37b2','e6c63afeeac23474b6f4a0440c25c4bcacf93e4057ca3713d22c8e03ecad460d','aea89b850b40ad7ac2e7cd289dd4e240744a75ff1ab5c2abb7c4af7cfe24003f','1bbc276423a9fd63c44f494a47f2d9bc87d85219982d44673d1141f27862ff5d','6c7f060be4da9621e2f04d1578d32377403ca5dba965dc07c310d10fdcbbe211','a4798dafcceec05ec3cb1750ed23b5fbe4b64ea4f0f2e74a7f9cd79984fd8991','635b34676a95af9705633e667b50fad144624ac24c2ce0bbfbcaea54f7abc7a6','d904a023c5b78283ac5703d76e3254a314d22ccacb9b07ba1a5a07e75ddb7f15','715d06bc845c66895bbe1d60ee52267eb6633ba004e78b74cc868b6f8835451f']
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    param = {'resource':md5,'apikey':api[i%len(api)],'allinfo': '0'}
    data = urllib.urlencode(param)
    result = urllib2.urlopen(url,data)
    jdata =  json.loads(result.read())
    t = 60/4/len(api)
    time.sleep(t)
    if jdata['response_code']==0:
        return None
    return str(jdata["positives"])+"/"+str(jdata["total"])


f=open(sys.argv[1],"rb")
s=f.read()
f.close()

domain = sys.argv[2]

s=s.split("\n")
list_url=[]
s[0]+=",Request,URL,Virustotal"
i_md5 = s[0].split(",").index("md5")
i=1
for x in s[1:]:
    x = x.split(",")
    if len(x) < 12:
        continue
    link = x[0]
    md5 = x[i_md5]
    try:
        a = str(request_url(link,domain))
        s[i]+=","+a
        b = str(scan_vt(md5,i))
        s[i]+=","+b
        print i,a,b
    except:
        s[i]+=",error"
    i+=1

        
f=open(sys.argv[1],"wb")
for x in s:
    f.write(x+'\n')
f.close()
