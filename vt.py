#!/usr/bin/env python3
#
# vt.py
# Handler for VirusTotal, given a free API.
#
# Bandwidth:
# Privileges	public key
# Request rate	4 requests/minute
# Daily quota	5760 requests/day
# Monthly quota	Uncapped requests/month
#
# Given the bandwidth, and the fact that one must request a url to be checked,
# and then request the results, the amount of urls classified per minute or day is n/2.
# We can receive 5760/2 or 2880 URLs per day. =]
#
# url: The URL that should be scanned. This parameter accepts a list of URLs 
# (up to 4 with the standard request rate) so as to perform a batch scanning request with one single call. The URLs must be separated by a new line character.

# https://stackoverflow.com/questions/22698244/how-to-merge-two-json-string-in-python
# Merge two json strings to one json
import requests, logging, time


class VirusTotal:

    def __init__(self):
        self.api = "06152a7ad29de8672ae94b27e7079f2911b0c64f9c63f4cb516113c9919420a1"
        logging.basicConfig(filename='vt.log', level=logging.DEBUG, format='%(asctime)s %(message)s')
        return

    def request(self, url):
        '''
            Given a url, will get the json results.
        '''
        print("[ ] Sending url...")
        try:
            addResponse = self.add_url(url)
        except:
            print("Waiting 60s...")
            addResponse = self.add_url(url)
            pass

        if ('successfully' in addResponse['verbose_msg']):
            print("[+] URL Added: {}".format(url))
        else:
            logging.debug(addResponse)
            #print(json_response['verbose_msg'])
            return

        results = self.results(addResponse['scan_id'])
        return results

    def add_url(self, url):
        '''
            Adds a domain/url/ip to vt queue to analyze. 
        '''  
        params = {'apikey': self.api, 'url': url}
        response = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', data=params)
        if (response.status_code == 403):
            logging.debug("403: {}".format(url))
            print("403") # DEBUGGING
            return
        try:
            json_response = response.json()
        except:
            print("Waiting 60s...")
            time.sleep(60)
            response = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', data=params)
            if (response.status_code == 403):
                logging.debug("403: {}".format(url))
                print("403") # DEBUGGING
                return
            json_response = response.json()
            pass
        return json_response
    
    def results(self, scan_id):
        '''
            Gets the results of a domain/url/ip request.
        '''
        params = {'apikey': self.api, 'resource':scan_id}
        headers = {"Accept-Encoding": "gzip, deflate",\
            "User-Agent" : "gzip,  My Python requests library example client or username"}
        response = requests.post('https://www.virustotal.com/vtapi/v2/url/report', params=params, headers=headers)
        json_response = response.json()
        return json_response