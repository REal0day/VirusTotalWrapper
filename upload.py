#!/usr/bin/env python3
#
# Name: VT upload
# Description: Determines if malware has already been uploaded. if it hasn't, upload. Get results on malware.
from os import listdir, getcwd
from os.path import isfile, join, exists
import hashlib, requests

class upload:

    def __init__(self):
        self.apikey = self.get_api()
        self.malDir = self.malware_directory()
        self.malware_list = self.filename_list(self.malDir)

    def get_api(self):
        self.apikey = input("API Key?: ")
        return self.apikey

    def malware_directory(self):
        '''
            Determines where the directory containin malware is located.
        '''
        ans = input("Current directory is: {}\nIs this the malware directory? (y/n): ".format(getcwd()))
        if (ans.lower() == "yes" or ans.lower() == "y"):
            return getcwd()
        
        elif (ans.lower () == "no" or ans.lower() == "n"):
            path = self.get_path()
            return path

        else:
            print("Answer not understood. Please try again.")
        
        self.malware_directory()

    def get_path(self):
        '''
            Gets path of malware directory
        '''
        path = input("Enter path: ")
        print(path)
        if exists(path):
            return path
        
        else:
            print("Path not understood.")
        
        self.get_path()


    def get_sha256(self, filename):
        '''
            Given a file, this will gather the 
        '''
        filename = self.malDir + "/" + filename   # Gives full path of file
        BLOCKSIZE = 65536
        hasher = hashlib.sha256()
        with open(filename, 'rb') as afile:
            buf = afile.read(BLOCKSIZE)
            while len(buf) > 0:
                hasher.update(buf)
                buf = afile.read(BLOCKSIZE)
        return hasher.hexdigest()

    def collect_sha256(self, malware_list):
        '''
            Given a list of filenames.
            open each up and get the sha256 of the file.
        '''
        sha_list = []
        for i in range(0, len(malware_list)):
            sha_hash = self.get_sha256(malware_list[i])
            sha_list.append(sha_hash)
        self.sha_list = sha_list
        return


    def filename_list(self, mypath):
        self.malware_list = [f for f in listdir(mypath) if isfile(join(mypath, f))]
        return self.malware_list

    def upload_malware(self, filename):
        url = 'https://www.virustotal.com/vtapi/v2/file/scan'
        params = {'apikey': self.apikey}

        fullpath = self.malDir + "/" + filename
        files = {'file': (filename, open(fullpath, 'rb'))}
        response = requests.post(url, files=files, params=params)
        return response
        #return response.json()

    def results(self, scan_id):
        '''
            Gets the results of a file request.
            Input can be scan_id or "resource"
        '''
        # These are for the request to VT's server
        params = {'apikey': self.apikey, 'resource':scan_id}
        headers = {"Accept-Encoding": "gzip, deflate",\
            "User-Agent" : "gzip,  My Python requests library example client or username"}
        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=headers)

        # There's a case where the response is empty
        if not (response):
            return

        json_response = response.json()
        return json_response

    def get_report(self, scan_id):
        '''
            Given a scan_id
            get the report of a malicious file from VT
        '''
        result = self.results(scan_id)
        if (self.results_completed):
            # Put result in csv
        
        else:
            time.sleep(60)
            print("Analysis of Malware not complete. Sleeping 60s..."))
            self.get_report(scan_id)
        return

    def results_completed(self, result):
        if (result['response_code'] is not 1):
            return False
        return True


    def driver(self, filename):
        response = self.upload_malware(filename)
        scan_id = response.json()['scan_id']
        self.get_report(scan_id)

        if (result['response_code'] is not 1):
            self.driver(filename)

        return

def main():
    c = upload()
    print(c.malware_list)
    c.sha_list = c.collect_sha256(c.malware_list)
    return

if __name__ == "__main__":
    main()