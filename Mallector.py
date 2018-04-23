#!/usr/bin/env python3
#
# Mallector.py
# Collect Malicious URIs and stores them in 
# a file called "potential"
# 1. Collect links from streams
# 2. Delete Dupes
# 3. Clean
# 4. Store in file.
import feedparser, logging, re
from urllib.parse import urlparse

class Mallector:

    def __init__(self):
        self.malfeeds = open('malware-feeds', 'r').read().splitlines()
        self.potential_list = []
        logging.basicConfig(filename='Mallector.log', level=logging.DEBUG, format='%(asctime)s %(message)s')
        return
    
    def update_feeds(self):
        self.malfeeds = open('malware-feeds', 'r').read().splitlines()
        return

    def has_both(self, domain_string):
        parse = urlparse(domain_string)
        result = '/' in parse.path  # If / in parsed path, then it has both
        return result
    
    def domain_splitter(self, domain_string):
        uri_list = [domain_string]

        # If domain parsed the string and has a 'netloc', the 'path' is the file location
        if (urlparse(domain_string).netloc): 
            page = urlparse(domain_string).netloc + urlparse(domain_string).path
            uri_list.append(page)
            return uri_list
        
        domain = re.match('^[^\/]*', domain_string).group()
        uri_list.insert(0, domain)
        return uri_list

    def find_domain(self, domain_string):

        # REGEX THE STRING THAT HAS DOMAIN IN IT HERE #
        # Case 0: Domain is just an IP or something.com
        # Domain Only
        if ('/' not in domain_string):
            domain = domain_string
            return

        # Case 1: Until space. 'textspeier.de (2017/12/04_18:50)'
        # Domain Only
        if (' ' in domain_string):
            spacer = domain_string.split()
            domain = spacer[0]  # The domain is first, the date is second for MalwareDomainList
            return domain
        
        # Case 2: String has both a file and domain in it.
        # This should be the last case
        if (self.has_both(domain_string)):
            uri_list = self.domain_splitter(domain_string)
            return uri_list
        
        # Case 3: 9.9.9.9
        
        print("find_domain broke. Check log.")
        logging.debug("find_domain broke. {}".format(domain_string))
        return
    
    def malc0de_feed_parser(self, feed):
        value_string = feed['items'][i]['summary_detail']['value']
        value_list = value_string.split(' ')
        domain_string = value_list[1][:-1]
        return domain_string

    def collect(self):
        # Goes through all the feeds in the file "malware-feeds"
        for i in range(0,len(self.malfeeds)):
            url = self.malfeeds[i]
            feed = feedparser.parse(url)

            # Goes through all the potentially malicious URIs in a specific feed
            for i in range(0,len(feed['items'])):

                # SPECIFIC FOR //malc0de.com/rss/
                if (url == 'http://malc0de.com/rss/'):
                    domain_string = malc0de_feed_parser(feed)
                
                if (url == 'https://cybercrime-tracker.net/rss.xml'):
                    

                result = self.find_domain(domain_string)

                if (type(result) == str):
                    self.potential_list.append(result)

                # Checks to see if domain_string reutrned a list containing
                # a domain and a domain w/ a file.
                # The list shouldn't be bigger than 2. If so somethign strange happened.
                if (type(result) == list):

                    # Checks to see if list is bigger than 2. It shouldn't ever.
                    if (len(result) > 2):
                        logging.debug("List bigger than 2: {}".format(result))

                    for i in range(0,len(result)):
                        self.potential_list.append(result[i])
        
        # Removes dupes
        self.potential_list = set(self.potential_list) 

        print("List of pMaliciousDomains: {}".format(len(self.potential_list)))
        return
