#!/usr/bin/env python3
import requests, sys

base = "https://extreme-ip-lookup.com/csv/"

filename = sys.argv[2]

all_ips = open(filename, "r").read().split()

csv = ""
x = 0
for ip in all_ips:
    url = base + ip
    r = requests.get(url)
    csv += r.text + "\n"
    print("{}/{}: {}\n{}\n\n".format(x, len(all_ips), ip, r.text))
    x += 1
    if (x % 100):
        with open("Full_57.csv", "a") as f:
            f.write(csv)
        csv = ""