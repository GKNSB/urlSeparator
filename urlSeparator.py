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

for folder in os.listdir(lepusFindingsDir):
    cleanurls = []
    urls = []

    if folder in domainsToProcess or "all" in domainsToProcess:

        print(f"[*] Processing {folder}")
        folderFiles = os.listdir(os.path.join(lepusFindingsDir, folder))

        if "urls.csv" in folderFiles:
            with open(os.path.join(lepusFindingsDir, folder, "urls.csv"), "rb") as urlsFile:
                for line in urlsFile.readlines():
                    urls.append(line.decode("utf-8").strip())

        if urls:
            wildcards = []
            if "wildcards.csv" in folderFiles:
                with open(os.path.join(lepusFindingsDir, folder, "wildcards.csv"), "rb") as wildcardsFile:
                    for line in wildcardsFile.readlines():
                        wildcardName = line.decode("utf-8").split("|")[0]

                        if wildcardName.startswith("."):
                            wildcardName = wildcardName[1:]

                        wildcardIP = line.decode("utf-8").split("|")[1]
                        wildcards.append([wildcardName, wildcardIP.strip()])

            if wildcards:
                for wildcard in wildcards:
                    for url in urls:
                        hostname = urlparse(url).netloc.split(":")[0]

                        ARecords = []
                        with open(os.path.join(lepusFindingsDir, folder, "resolved_public.csv")) as resolutionsFile:
                            for resline in resolutionsFile:
                                if re.findall(f"{hostname}\|(.*)$", resline.strip()):
                                    for IP in re.findall(f"{hostname}\|(.*)$", resline.strip())[0].split(","):
                                        ARecords.append(IP)

                        if re.search(f"\.{wildcard[0]}", url) and wildcard[1] in ARecords:
                            pass
                        else:
                            cleanurls.append(url)

            else:
                cleanurls = urls

    if cleanurls:
        with open(output, "a") as outfile:
            for cleanurl in list(set(cleanurls)):
                outfile.write(f"{cleanurl}\n")
