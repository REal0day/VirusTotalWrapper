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
        self.potentials = None
        self.potentials_file = 'data/Potentials.txt'
        self.blk = None
        self.blk_file = 'data/GlobalBlacklist.txt'
        self.analysis = None
        self.analysis_file = 'data/Full-Analysis.txt'
        self.processed = None
        self.processed_file = 'data/Processed_file.txt'
        logging.basicConfig(filename='logs/Mallector.log', level=logging.DEBUG, format='%(asctime)s %(message)s')
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
        
        print("find_domain broke. Check log.")
        logging.debug("find_domain broke. {}".format(domain_string))
        return
    
    def malc0de_feed_parser(self, value_string):
        value_list = value_string.split(' ')
        domain_string = value_list[1][:-1]
        return domain_string

    def collect(self, output_filename):
        # Goes through all the feeds in the file "malware-feeds"
        for i in range(0,len(self.malfeeds)):
            url = self.malfeeds[i]
            feed = feedparser.parse(url)

            # Goes through all the potentially malicious URIs in a specific feed
            for i in range(0,len(feed['items'])):

                # SPECIFIC FOR //malc0de.com/rss/
                if (url == 'http://malc0de.com/rss/'):
                    value_string = feed['items'][i]['summary_detail']['value']
                    domain_string = self.malc0de_feed_parser(value_string)
                
                if (url == 'https://cybercrime-tracker.net/rss.xml'):
                    domain_string = feed['items'][i]['title']

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
        self.potential_list = list(self.potential_list)

        # Remove any domains already collected.
        out = open(output_filename, 'a')
        for item in self.potential_list:
            out.write("%s\n" % item)
        out.close()
        print("{} of pMaliciousDomains saved to {}".format(len(self.potential_list), output_filename))
        return
    
    def dedupe(self, filename):
        '''
            Eliminates duplicates in file.
        '''
        old_lines = open(filename).readlines()
        number_of_lines_before = len(old_lines)
        uniqlines = set(old_lines)
        current_number = len(uniqlines)
        number_of_dupes = number_of_lines_before - current_number
        if (number_of_dupes > 1):
            print("{} duplicates in {}!".format(number_of_dupes, filename))
            open(filename, 'w').writelines(set(uniqlines))
            self.number_of_domains(current_number)

        elif (number_of_dupes == 1):
            print("{} duplicate in {}!".format(number_of_dupes, filename))
            open(filename, 'w').writelines(set(uniqlines))
            self.number_of_domains(current_number)

        else:
            print("No duplicates present in {}".format(filename))
            self.number_of_domains(current_number)
        return
    
    def number_of_domains(self, domain_number):

        if (domain_number > 1):
            print("File has {} domains.".format(domain_number))

        elif (domain_number == 1):
            print("File has {} domain.".format(domain_number))

        elif (domain_number == 0):
            print("File has no domains.")

        else:
            print("Current number of domains is <0. Seems odd.")
            logging.debug('dedupe function returning less than 0.')
        return
    
    def dedupe_all(self):
        '''
            Removes duplicates in each individual file.
        '''
        self.dedupe(self.blk_file)
        self.dedupe(self.processed_file)
        self.dedupe(self.potentials_file)
        return
    
    def already_processed(self):
        count = 0
        blk = open(self.blk_file, 'r')
        potentials = open(self.potentials_file, 'r')
        processed = open(self.processed_file, 'r')

        blk_list = blk.read().split()
        potentials_list = potentials.read().split()
        processed_list = processed.read().split()

        already_processed_list = processed_list + blk_list

        for item1 in range(0,len(already_processed_list)):
            for item2 in range(0,len(potentials_list)):
                try:
                    if (already_processed_list[item1] == potentials_list[item2]):
                        potentials_list.remove(already_processed_list[item1])
                        count += 1
                except:
                    pass
        
        blk.close()
        potentials.close()
        processed.close()

        print("{} domains already processed for potential.".format(count))
        print("{} potentially malicious domains.".format(len(potentials_list)))

        f = open(self.potentials_file, 'w')
        for i in range(0, len(potentials_list)):
            f.write(potentials_list[i] + "\n")
        f.close()

        return

    def removed_preprocessed_blacklist_domains(self):
        '''
            Removes domains that have been blacklisted
        '''
        blk_file_lines = open(self.blk_file, 'r').readlines()
        potential_lines = open(self.potentials_file, 'r').readlines()

        uniqlines = set(old_lines)
        current_number = len(uniqlines)
        number_of_dupes = number_of_lines_before - current_number
        return
        
