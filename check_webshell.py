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
    api = ['da0c17684c7b5b44b8896130ffa3ce3038f05d1906c6eac698d731eb685e37b2','e6c63afeeac23474b6f4a0440c25c4bcacf93e4057ca3713d22c8e03ecad460d','aea89b850b40ad7ac2e7cd289dd4e240744a75ff1ab5c2abb7c4af7cfe24003f','1bbc276423a9fd63c44f494a47f2d9bc87d85219982d44673d1141f27862ff5d','6c7f060be4da9621e2f04d1578d32377403ca5dba965dc07c310d10fdcbbe211','a4798dafcceec05ec3cb1750ed23b5fbe4b64ea4f0f2e74a7f9cd79984fd8991','635b34676a95af9705633e667b50fad144624ac24c2ce0bbfbcaea54f7abc7a6','d904a023c5b78283ac5703d76e3254a314d22ccacb9b07ba1a5a07e75ddb7f15','715d06bc845c66895bbe1d60ee52267eb6633ba004e78b74cc868b6f8835451f',
    '6e92397035501237a8386cb268e5abe97c7f1f5381dc6161eabc461a72964857','f91f30096f9b73f502a47bcd5f0facf7263ec4457bc24cc45cc6de823eaa8b71','4d85000461cc03f6b06db4697238d7d60332751f86eac0c11263d650c2d6038b','097aee125146449efa78198764f1d70d2ffa7368b94fcf0c34c2fea8c5431e54','019a3a047d3bb117e8ae3cd6aea90481d8f7d73e3e4dd204e00b8f33aac9f3ea','6049c3bcfa4e4746de025065d16a48d07632ba247a6329e2a1952f73f782f8df','30cb21d628ecb6718d87f193c4f6b74ca402c453fe9e2ba8ce7830d01f16cdbe','e009433efccf4573e164c6b9e6dad69002ad6dc04cd4e8dc7f1cc6d3b70718ee','ac3c2e6dd9e2f3607c1573b84b1a10c172e53e50efc1b4a549885ffbe734cad9','92a6a5843f994963c4efb6f93d78990db1a7fc83171f5fdd8a98d0beade306cd',
    '9987aa89242e53460ea4fc337e739388f5778875788b4515e1d8a3ac704b47df','6b62c01584d4303bc95a07d9db3404ef1fc957c58361390de8d16367d106e5cc',
    'f88158de8f8dd5fc34acf634b876581df55b96c37f6c48d0ebfef47081bfc8c8','4b3b343ddf6f79938b32ec1516da8df4c305598b4c158f7774777954c477d0e6','a6ec7205fd49689cad100bee537ffe88dc9e30af609943ea9379b65eae69f486','2cafd811b992b3c4f1395b46ea2b100df3280df4407d34980bd7ae44c2bccaa9','61aa9e070df6f5d850946e957cbb2768a8f18a04211caa2de8001944391aea5c']
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
i_md5 = s[0].split(",").index("MD5")
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
