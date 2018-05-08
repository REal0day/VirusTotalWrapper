#!/usr/bin/env python3
#
# vt.py
# Handler for VirusTotal, given a free API.
#
# Bandwidth:
# Privileges	public key
# Request rate	4 requests/minute
# Daily quota	5760 requests/day
#
# Privileges	paid key
# Request rate	25 requests/minute
# Daily quota	36,000 requests/day
#
# Given the bandwidth, and the fact that one must request a url to be checked,
# and then request the results, the amount of urls classified per minute or day is n/2.
# We can receive 5760/2 or 2880 URLs per day. =]
#
# url: The URL that should be scanned. This parameter accepts a list of URLs 
# (up to 4 with the standard request rate) so as to perform a batch scanning request with one single call. The URLs must be separated by a new line character.

# https://stackoverflow.com/questions/22698244/how-to-merge-two-json-string-in-python
# Merge two json strings to one json
from pathlib import Path
from urllib.parse import urlparse
import Mallector, requests, logging
import time, os, datetime, sys, re

class VirusTotal:

    def __init__(self):
        self.keyblade = None
        self.keyring = None
        self.new_key = True
        self.key_index = 0
        self.collector = Mallector.Mallector()
        self.av_list = open('config/VT-AVs', 'r').read().splitlines()
        self.potentials = None
        self.potentials_file = 'data/Potentials.txt'
        self.blk = None
        self.blk_file = 'data/GlobalBlacklist.txt'
        self.analysis = None
        self.analysis_file = 'data/Full-Analysis.csv'
        self.processed = None
        self.processed_file = 'data/Processed_file.txt'
        self.cycles = 0
        self.reprocess_line = 0 # Used to determine what line the reprocessing function is on
        self.data = [self.analysis_file, self.blk_file, self.potentials_file, self.processed_file]
        logging.basicConfig(filename='logs/vt.log', level=logging.DEBUG, format='%(asctime)s %(message)s')
        return
    
    def multiple_keyblades(self):
        if (type(self.keyblade) == list):
            return True
        return False
    
    def files_exist(self, filename):
        the_file = Path(filename)
        if (the_file.is_file()):
            return True
        return False
    
    def inspect(self, input_filename):
        '''
            Driver.
            1. Reads domain list from file
            2. Creates output file
            3. Gives url to 
        '''
        analysis = open(self.analysis_file, 'a')
        ifile = open(input_filename, 'r')
        domainList = ifile.read().split()

        for i in range(0, len(domainList)):
            result = self.request(domainList[i])
            self.analysis.write(str(result))
        ifile.close()
        analysis.close()
        return

    def inspect_to_csv(self, input_filename):
        '''
            Driver.
            1. Reads domain list from file
            2. Creates output file
            3. Formats output file
            4. Gives url to 
        '''
        # Input file for domain_list
        ifile = open(input_filename, 'r')
        # Analysis Output file. Contains all AV results per request
        
        # DEBUG TEST #
        #analysis = open(self.analysis_file, 'a')
        analysis = open('test-one.csv', 'a')
        self.csv_format() # Formats output file for csv
        domainList = ifile.read().split()

        for i in range(0, len(domainList)):
            print("{}/{}".format(i, len(domainList)))
            
            try:
                result = self.request(domainList[i])
                domain = result['url']
                row = domain + ","
                ts = time.time()
                timestamp = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                row += ",{},,,,,".format(timestamp) # This is the number of columns until the spreadsheet records AVs.
                scanResults = result['scans']
                
                for i in range(0, len(self.av_list)):
                    try:
                        row += self.cell(scanResults[self.av_list[i]])
                    except:
                        pass
                    row += ","
                
                row += "\n"
                try:
                    analysis.write(row)
                except:
                    logging.exception("message")

            except:
                print("Special Excpetion. Something Broke.")
                
                try:
                    self.analysis.write("BROKEN\n")

                except:
                    logging.exception("message")

                logging.exception("message")
                pass

        ifile.close()
        analysis.close()
        return

    def persistent_analysis(self):
        '''
            Driver.
            1. Reads domain list from file
            2. Creates output file
            3. Formats output file
            4. Gives url to 
        '''
        # Determine if files exist, if they don't create them.
        # Full-Analysis.txt
        if (self.files_exist(self.analysis_file)):
            self.analysis = open(self.analysis_file, 'a')

        else:
            self.csv_format() # Formats output file for csv
            self.analysis.flush()
            os.fsync(self.analysis.fileno())

        # GlobalBlacklist.txt
        if not (self.files_exist(self.blk_file)):
            self.blk = open(self.blk_file, 'a')
            self.blk.close()
        
        # Processed_file.txt
        if not (self.files_exist(self.processed_file)):
            self.processed = open(self.processed_file, 'a')
            self.processed.close()

        # Blacklist output file. New file each day.
        # Removing blacklist file per day. Going to make it one master blacklist.
        #with DailySave.RotatingFileOpener('blacklist', prepend='blacklist-', append='.txt') as bl:

        while True:

            # Number of cycles
            print("Number of cycles: {}".format(self.cycles))

            # Updates feeds
            self.collector.update_feeds()

            # Gathers all new domains from feeds
            self.collector.collect(self.potentials_file)

            # Cleans all duplicates in all three files.
            self.collector.dedupe_all()

            # Cleans all domains that have already been processed
            self.collector.already_processed()

            # Creates a list of potentially malicious domains from potential.txt
            new_potentials = self.new_pdomains()
            if (new_potentials):

                # Analysis Output file. Contains all AV results per request
                with open(self.potentials_file, 'r') as self.potentials:
                    domainList = self.potentials.read().split()

                for i in range(0, len(domainList)):
                    print("{}/{}".format(i, len(domainList)))
                    
                    try:
                        result = self.request(domainList[i])
                        print("result: {}".format(result))

                        # Determine if domain is malicious
                        if (self.is_malicious(result)):
                            print('{} is MALICIOUS!'.format(domainList[i]))

                            with open(self.blk_file, 'a') as self.blk:
                                clean_domain = self.domain_clean(domainList[i])
                                self.blk.write(clean_domain + "\n")
                                self.blk.flush()
                                os.fsync(self.blk.fileno())

                        else:
                            print('{} is NOT malicious!'.format(domainList[i]))
                            with open(self.processed_file, 'a') as self.processed:
                                self.processed.write(domainList[i] + "\n")
                                self.processed.flush()
                                os.fsync(self.processed.fileno())

                        self.csv_output(result)

                    except:
                        print("Check persistent analysis..")
                        logging.debug("Check persistent analysis.\n")
                        pass
                
                self.analysis.close()
                
            else:
                logging.info("No new potentially malicious domains.")
                logging.info("Reprocessing starting on line {}".format(self.reprocess_line))
                
                # Reprocessed the processed list to see if anything has changed
                self.reprocess()

            # Keep track of the number of times this program has looped.
            self.cycles += 1

        return
    
    def reprocess(self):
        self.processed = open(self.processed_file, 'r')
        processed_list = self.processed.read().split()
        start = time.time()
        time_lapsed = time.time()

        while ((time_lapsed - start) < 3600):
            print("{}/{}".format(self.reprocess_line, len(processed_list)))
            
            try:
                result = self.request(processed_list[self.reprocess_line])

                # Determine if domain is malicious
                if (self.is_malicious(result)):
                    print('{} is MALICIOUS!'.format(processed_list[self.reprocess_line]))

                    with open(self.blk_file, 'a') as self.blk:
                        clean_domain = self.domain_clean(processed_list[self.reprocess_line])
                        self.blk.write(clean_domain + "\n")
                        self.blk.flush()
                        os.fsync(self.blk.fileno())

                else:
                    print('{} is NOT malicious!'.format(processed_list[self.reprocess_line]))
                    with open(self.processed_file, 'a') as self.processed:
                        self.processed.write(processed_list[self.reprocess_line] + "\n")
                        self.processed.flush()
                        os.fsync(self.processed.fileno())

                self.csv_output(result)

            except:
                print("Check reprocess...")
                logging.debug("Check reprocess.\n")
                pass

            # This ensure that the reporcess_line counter won't go past the range of number of lines in the file.
            if (self.reprocess_line == len(processed_list)):
                self.reprocess_line = 0
            else:
                self.reprocess_line +=1

            time_lapsed = time.time()

        return

    def csv_output(self, result):
        '''
            Writes to Full-Analysis.csv
        '''
        domain = result['url']
        row = domain + ","
        ts = time.time()
        timestamp = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
        row += "{},,,,,,".format(timestamp) # This is the number of columns until the spreadsheet records AVs.
        scanResults = result['scans']
        
        for i in range(0, len(self.av_list)):
            try:
                row += self.cell(scanResults[self.av_list[i]])
            except:
                pass
            row += ","
        
        row += "\n"
        self.analysis.write(row)
        self.analysis.flush()
        os.fsync(self.analysis.fileno())
        return
    
    def key_rotate(self):
        if ((self.key_index) == 9):
            self.key_index = 0
            return
        
        else:
            self.key_index += 1
            return

    def request(self, url):
        '''
            Given a url, will get the json results.
        '''
        # This section sends the url
        print("[ ] Sending url...{}".format(url))
        
        try:
            addResponse = self.add_url(url)
        
        except:
            print("request Waiting 60s...")
            time.sleep(60)
            #self.blk.flush()
            #os.fsync(self.blk.fileno())
            return self.request(url)

        # This should help when addResponse returns nothing.
        if (addResponse):

            if ('successfully' in addResponse['verbose_msg']):
                print("[+] URL Added: {}".format(url))
            else:
                logging.debug("addResponse: ".format(addResponse))
                #print(json_response['verbose_msg'])
                return

            # This section you receive the JSON
            results = self.results(addResponse['scan_id'])
            return results
        else:
            print("addResponse: {}\nRe-requestin in 30s.")
            time.sleep(30)
            return self.request(url)

    
    def reattack(self, response):
        '''
            Given the response from the server AND self.keyring exists,
            this function will rotate the key, and send a new request.
        '''

        return

    def domain_clean(self, string):
        '''
            Given a URL/URN, this function will return the domain [and [subdomain[s]]
        '''
        domain = urlparse(string)

        if (domain.netloc):
            return domain.netloc

        elif (domain.path[0] != "/"):

            if ("/" in domain.path):
                # Get string until /
                redomain = re.match("[^\/]*", domain.path).group(0)
                return redomain
            else:
                return(domain.path)

        else:
            logging.debug("Error while cleaning a malicious domain before appending to blacklist\nDomain: {}".format(item))

        return


    def add_url(self, url):
        '''
            Adds a domain/url/ip to vt queue to analyze. 
        '''
        # These are for enabling key rotation
        origin = time.time()
        #self.new_key = True

        # These are for the request to VT's server
        if (self.keyring):
            params = {'apikey': self.keyring[self.key_index], 'url': url}
        
        else:
            params = {'apikey': self.keyblade, 'url': url}

        print("params: {}".format(params))
        
        response = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', data=params)
        
        print("response: {}".format(response))

        if (response.status_code == 403):
            logging.debug("403: {}".format(url))
            print("403: ERROR WITH API-KEY") # DEBUGGING
            sys.exit(0)       

        # THIS THE PROBLEM RIGHT HERE.
        # THIS SHIT WON'T ROTATE KEYS CORRECTLY
        if (response.status_code == 204):
            logging.debug("204: {}".format(url))

            # If they're multiple API keys
            if (self.keyring):

                # Rotate key from 0 to 1.
                self.key_rotate()
                #self.new_key = True
                if (self.key_index != 0):
                    return self.add_url(url)

                else:
                    try:
                        self.collector.already_processed()
                    except:
                        pass
                    end = time.time()
                    time_lapsed = end - origin
                    
                    # If 60s has passed since the first key started, cooldown is over, reset keys and start over.
                    if (time_lapsed > 60):
                        #self.new_key = True
                        return self.add_url(url)
                    
                    else:
                        print("Keyring sleep: {}s".format(60-time_lapsed))
                        time.sleep(60 - time_lapsed)
                        response = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', data=params)

                #else: # Branch to switch keys
                    #self.new_key = True
                    #self.key_rotate()

            else:
                print("add_url Waiting 60s...")
                time.sleep(60)
                response = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', data=params)
                    
        json_response = response.json()
        print(response.text)
        return json_response
    
    def new_pdomains(self):
        
        # Input file for domain_list
        try:
            self.potentials = open(self.potentials_file, 'r')

        except FileNotFoundError:
            logging.info("{} not found. Creating one now.".format(self.potentials_file))
            self.potentials = open(self.potentials_file, 'a')
            self.potentials.close()
            self.potentials = open(self.potentials_file, 'r')
            logging.exception("message")
            pass     

        potentials_list = self.potentials.read().split()
        self.potentials.close()        

        try:
            blkout = open(self.blk_file, 'r')

        except FileNotFoundError:
            logging.info("{} not found. Creating one now.".format(self.blk_file))
            blkout = open(self.blk_file, 'a')
            blkout.close()
            blkout = open(self.blk_file, 'r')
            logging.exception("message")
            pass

        blkout_list = blkout.read().split()
        blkout.close()

        try:
            processed = open(self.processed_file, 'r')

        except FileNotFoundError:
            logging.info("{} not found. Creating one now.".format(self.processed_file))
            processed = open(self.processed_file, 'a')
            processed.close()
            processed = open(self.processed_file, 'r')
            logging.exception("message")
            pass

        processed_list = processed.read().split()
        processed.close()

        temp_total_list = blkout_list + processed_list
        if not (list(set(potentials_list) - set(temp_total_list))):
            return False
        return True

    def results(self, scan_id):
        '''
            Gets the results of a domain/url/ip request.
        '''
        # These are for the request to VT's server
        if (self.keyring):
            params = {'apikey': self.keyring[self.key_index], 'resource':scan_id}
        
        else:
            params = {'apikey': self.keyblade, 'resource':scan_id}

        headers = {"Accept-Encoding": "gzip, deflate",\
            "User-Agent" : "gzip,  My Python requests library example client or username"}
        response = requests.post('https://www.virustotal.com/vtapi/v2/url/report', params=params, headers=headers)
        
        # There's a case where the response is empty
        if not (response):
            return
        json_response = response.json()
        return json_response
    
    def clean_json(self, jsonKinda):
        '''
            For whatever reason, VirusTotal gives you back a JSON that
            most libraries just don't like.
            None, single quotes and False are just a no-go.
            This will clean those up.
        '''
        clean = jsonKinda.replace("\'", "\"")
        clean = clean.replace("None", "0")
        clean = clean.replace("False", "0")
        clean = clean.replace("True", "1")
        return clean
    
    def csv_format(self):
        '''
            Creates a formatted csv, ready for data.
            Don't get output_file and output_filename confused.
            output_file is open.
        '''
        self.analysis = open(self.analysis_file, 'a')
        self.analysis.write("Domain,Timestamp,Detected,Clean,Suspicious,Malware,Malicious,ADMINUSLabs,AegisLab WebGuard,AlienVault,Antiy-AVL,Avira,Baidu-International,BitDefender,Blueliv,C-SIRT,Certly,CLEAN MX,Comodo Site Inspector,CyberCrime,CyRadar,desenmascara.me,DNS8,Dr.Web,Emsisoft,ESET,Forcepoint ThreatSeeker,Fortinet,FraudScore,FraudSense,G-Data,Google Safebrowsing,K7AntiVirus,Kaspersky,Malc0de Database,Malekal,Malware Domain Blocklist,Malwarebytes hpHosts,Malwared,MalwareDomainList,MalwarePatrol,malwares.com URL checker,Nucleon,OpenPhish,Opera,Phishtank,Quttera,Rising,SCUMWARE.org,SecureBrain,securolytics,Spam404,Sucuri SiteCheck,Tencent,ThreatHive,Trustwave,Virusdie External Site Scan,VX Vault,Web Security Guard,Webutation,Yandex Safebrowsing,ZCloudsec,ZDB Zeus,ZeroCERT,Zerofox,ZeusTracker,zvelo,AutoShun,Netcraft,NotMining,PhishLabs,Sophos,StopBadware,URLQuery\n")
        self.analysis.flush()
        os.fsync(self.analysis.fileno())
        return

    def cell(self, av_result):
        '''
            Given a single av_result by vt,
            this will format an output.
            ex. {'detected': False, 'result': 'clean site'}
                'False/clean site'
        '''
        cell = str(av_result['detected'])
        cell += ";" + av_result['result']
        
        # Sometimes there aren't details.
        try:
            cell += ";" + av_result['detail']
        except:
            logging.exception("message")
            pass

        return cell

    def malcheck(self, url):
        result = self.request(url)
        if (self.is_malicious(result)):
            conclusion = "MALICIOUS"
        elif (not self.is_malicious(result)):
            conclusion = "NOT malicious"
        else:
            print('mal_check broke, but because of is_malicious()')
            logging.debug('mal_check broke, but because of is_malicious()')
        print("{}: {}".format(conclusion, url))
        return 
    
    def is_malicious(self, result):
        '''
            Determines if a domain is malicious.
            If both Forcepoint ThreatSeeker and Fortinet return True,
            it is malicious.
        '''
        
        try:
            if ("clean" not in result['scans']['Forcepoint ThreatSeeker']['result']) & ("clean" not in result['scans']['Forcepoint ThreatSeeker']['result']):
                return True
        except:
            logging.warning("{} could not be determine as malicious or not. AVs on VT might not have analyzed domain.")
            logging.exception("message")
            pass
        return False


def main():
    print("Welcome to VirusTotalWrapper!")
    print("If you don't have an API-Key, get one for free at VirusTotal.com.")

    # Creates the VirusTotal Instance
    c = VirusTotal()

    while (type(c.keyblade) == (type(c.keyring))):
        keys = input("Do you have multiple API keys? (y/n) ")

        if ((keys == 'y') or (keys == 'Y')):
            kingdom_hearts = input("Please provide the location of the file that contains your API-keys.\n ( /home/user/keys ): ")
            
            try:
                with open(kingdom_hearts, 'r') as kh:
                    c.keyring = kh.read().split()

            except (FileNotFoundError, IsADirectoryError) as e:
                print("Unable to find the file.")
                break
            
            key_number = input("There are {} keys. Would you like to use some or all? (some/all): ")

            if ((key_number == 'some') or (key_number == 'Some')):
                num_of_keys = input("How many: ")
                while (len(c.keyring) != (num_of_keys)):
                    del c.keyring[-1]
            elif ((key_number == 'all') or (key_number == 'All')):
                pass

        elif ((keys == 'n') or (keys == 'N')):
            keyblade = input("Enter your Key: ")
            c.keyblade = keyblade

        else:
            pass

    # Start running the analysis
    c.persistent_analysis()

    return

if __name__ == "__main__":
    main()
