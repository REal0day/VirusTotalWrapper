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

    def get_api(self):
        self.apikey = input("API Key?: ")
        return

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
        return

    def upload_malware(self, filename):
        url = 'https://www.virustotal.com/vtapi/v2/file/scan'
        params = {'apikey': self.apikey}
        files = {'file': (filename, open(filename, 'rb'))}
        response = requests.post(url, files=files, params=params)
        return response
        #return response.json()


def main():
    c = upload()
    c.malware_list = c.filename_list(c.malDir)     # This isn't working. why?
    print(c.malware_list)
    c.sha_list = c.collect_sha256(c.malware_list)
    return

if __name__ == "__main__":
    main()