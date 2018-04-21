#!/usr/bin/env python3
#
# Mallector.py
# Collect Malicious URIs and stores them in 
# a file called "potential"
# 1. Collect links from streams
# 2. Delete Dupes
# 3. Clean
# 4. Store in file.
import feedparser

class Mallector:

    def __init__(self):
        self.malfeeds = open('malware-feeds', 'r').read().splitlines()
        self.potential_list = []
        return
    
    def collect(self):
        # Goes through all the feeds in the file "malware-feeds"
        for i in range(0,len(self.malfeeds)):
            url = self.malfeeds[i]
            feed = feedparser.parse(url)

            # Goes through all the potentially malicious URIs in a specific feed
            for i in range(0,len(feed['items'])):
                self.potential_list.append(feed['items'][i]['title'])

        print("List of pMaliciousDomains: {}".format(len(self.potential_list)))
        return