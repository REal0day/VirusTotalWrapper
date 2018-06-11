#!/usr/bin/env python3
#
# Name: VT upload
# Description: Determines if malware has already been uploaded. if it hasn't, upload. Get results on malware.
from os import listdir, getcwd
from os.path import isfile, join
import hashlib, requests

class upload:

    def __init__(self):
        self.apikey = self.get_api()
        self.malDir = self.malware_directory()
        self.sha_list = self.sha256_list(self.malDir)
        

    def get_api(self):
        self.apikey = raw_input("API Key?: ")
        return

    def malware_directory(self):
        '''
            Determines where the directory containin malware is located.
        '''
        ans = raw_input("Current directory is: {}\nIs this the malware directory? (y/n): ".format(getcwd()))
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
        path = raw_input("Enter path: ")
        
        if os.path.exists(path):
            return path
        
        else:
            print("path not understood.")
        
        self.get_path()


    def get_sha256(self, filename):
        '''
            Given a file, this will gather the 
        '''
        BLOCKSIZE = 65536
        hasher = hashlib.sha256()
        with open(filename, 'rb') as afile:
            buf = afile.read(BLOCKSIZE)
            while len(buf) > 0:
                hasher.update(buf)
                buf = afile.read(BLOCKSIZE)
        return hasher.hexdigest()

    def sha256_list(self, mypath):
        self.sha_list = [f for f in listdir(mypath) if isfile(join(mypath, f))]
        return

    def upload_malware(self, filename):
        url = 'https://www.virustotal.com/vtapi/v2/file/scan'
        params = {'apikey': self.apikey}
        files = {'file': (filename, open(filename, 'rb'))}
        response = requests.post(url, files=files, params=params)
       return response.json()



def main():
    c = upload()

    return

if __name__ == "__main__":
    main()