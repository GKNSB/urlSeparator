#!/usr/bin/env python3

import os
import re
import shutil
from dns.resolver import resolve
from socket import gethostbyname
from urllib.parse import urlparse
from argparse import ArgumentParser, FileType

parser = ArgumentParser(prog="urlSeparator.py", description="I find urls in Lepus directories")
parser.add_argument("-d", "--domains", action="store", dest="domains", type=str, default="all", help="Domain output folders to process separated by commas (Default 'all')")
parser.add_argument("lepusFindingsDir", help="Location of Lepus findings directory", type=str)
parser.add_argument("output", help="Output file location", type=str)
args = parser.parse_args()

lepusFindingsDir = args.lepusFindingsDir
output = args.output
domainsToProcess = args.domains.split(",")

try:
    os.remove(output)
except:
    pass

for domain in domainsToProcess:
    print(f"[*] Processing {domain}")
    
    folderFiles = os.listdir(os.path.join(lepusFindingsDir, domain))
    urls = []
    cleanUrls = []
    wildcardDomains = []
    wildcardIps = []

    if "urls.csv" in folderFiles:
        with open(os.path.join(lepusFindingsDir, domain, "urls.csv"), "rb") as urlsFile:
            for line in urlsFile.readlines():
                urls.append(line.decode("utf-8").strip())

    if "wildcards.csv" in folderFiles:
        wildcards = []

        with open(os.path.join(lepusFindingsDir, domain, "wildcards.csv"), "rb") as wildcardsFile:
            for line in wildcardsFile.readlines():
                wcline = line.decode("utf-8").strip()

                wildcardDomains.append(wcline.split("|")[0].strip("."))
                wildcardIps.extend(wcline.split("|")[1].split(","))
        
    if urls:
        for url in urls:
            hostname = urlparse(url).netloc.split(":")[0]
            ips = []

            with open(os.path.join(lepusFindingsDir, domain, "resolved_public.csv"), "rb") as resFile:
                for line in resFile.readlines():
                    resline = line.decode("utf-8").strip()
                    if resline.startswith(hostname):
                        ips.extend(resline.split("|")[1].split(","))

            wcdMatch = False
            wciMatch = False

            for wcDom in wildcardDomains:
                if f".{wcDom}" in hostname:
                    wcdMatch = True
            
            for wcIp in wildcardIps:
                if wcIp in ips:
                    wciMatch = True

            if wcdMatch and wciMatch:
                pass
            else:
                cleanUrls.append(url)

    if cleanUrls:
        with open(output, "a") as outfile:
            for cleanurl in list(set(cleanUrls)):
                outfile.write(f"{cleanurl}\n")
