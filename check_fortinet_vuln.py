
import sys, getopt, os.path, os, urllib3
import requests 
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings()
#verifico se esiste il file EGBL.config
def usage():
    print ""
    print "######## Fortinet NSA checking tool ############"
    print "# Author:   Fabio Natalucci                    #"
    print "# Twitter: @fabionatalucci                     #"
    print "# Website: https://www.fabionatalucci.it       #"
    print "#                BIG THANKS TO...              #"
    print "#            NSA and Equation Group            #"
    print "#       and to Shadow Brokers for disclosure   #"
    print "################################################"
    print "USAGE: ./check_fortinet_ip -i IP"
    print ""
    print ""

def verifyConfig():
    if os.path.exists("EGBL.config"):
        print '## EGBL.config...OK'
    else: sys.exit(2)

def verifyVuln(n):
    try:
	r=requests.get("https://"+n, verify=False, headers={"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.11; rv:47.0) Gecko/20100101 Firefox/47.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language": "en-US", "Accept-Encoding": "gzip, deflate, br", "Connection": "close"})
        #r=requests.get('https://'+n, verify=False, timeout=10)
    except requests.exceptions.RequestException as e:   
	print e
        sys.exit(1)
    try:
	#debug print r.headers['ETag']
   	etag = r.headers['ETag'].replace('"',"").split('_',2)[-1]
    except KeyError:
        print '----> NOT VULNERABLE'
	print 'ETag header missing. Probably not running on Fortigate models 60, 60M, 80C, 200A, 300A, 400A, 500A, 620B, 800, 5000, 1000A, 3600 or 3600A.'
	sys.exit()

    if etag in open('EGBL.config').read():
        print ''
        print '----> VULNERABLE ! '
    else :
        print ''
        print '----> NOT VULNERABLE'


def main(argv):
    try:
        opts, args = getopt.getopt(argv, "hi:d", ["ip="])
    except getopt.GetoptError:
        usage()
        sys.exit(2)

    if not opts:
        usage()
        sys.exit(2)

    for opt, arg in opts:
        if opt == "-h":
            print '### HELP? ma LOL ###'
            sys.exit()
        elif opt == "-i":
            ipToCheck = arg
         

    print '## Checking IP:',arg

    print '## Verify EGBL...'
    verifyConfig()
     
    print '## Check vulnerability...'
    verifyVuln(ipToCheck)

if __name__ == "__main__":
    main(sys.argv[1:])
