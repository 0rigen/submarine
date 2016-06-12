import sys
import os
from os.path import basename
import urllib
import json
import subprocess
import re
import time
from datetime import datetime
import logging


# import asyncio

def findFile(target):
    target_files = []

    for root, dirs, files in os.walk('.'):
        for file in files:
            name = os.path.basename(file)
            if target in name:  # Found a file for my target
                if ".lst" in name:  # Found a list file
                    target_files.append(file)
    return target_files


# Resolve command line target
try:
    target = sys.argv[1]
    print("Targeting %s" % target)
except:
    print("I couldn't understand the target!")
    sys.exit(1)


def main():
    # Check to see if a folder already exists for that target
    if os.path.exists("%s/" % target):  # It does
        print("I already have data for this target; files will be updated.")
    else:  # It doesn't
        print("New Target!  Creating a home for the data...")
        try:
            subprocess.call(["mkdir", target])  # Create it
        except:
            print("Something went wrong creating the directory.  Permissions?")
            sys.exit(1)

    ##########################
    # Begin domain finding
    ##########################
    enumall(target)
    subbrute(target)


def enumall(target):
    # The call...
    subprocess.call(["/root/Code/submarine/enumall.sh", target])

    # Begin file processing by grabbing the new output
    os.chdir(target)  # Change PWD to the target directory
    cmd = ("mv /usr/share/recon-ng/*.lst .")  # Just build the command...
    subprocess.call(cmd, shell=True)  # Move any new .lst files into current directory
    files = findFile(target)  # Get all target-relevant .lst files

    latest = os.path.getctime(".")  # Establish a base time for comparison

    if not files:  # Nothing to process
        print("New new enumall output files to process...That's odd.")

    elif len(files) == 2:  # Multiple files exist
        for f in files:
            f_time = os.path.getmtime(f)  # Get timestamp of file
            if f_time > latest:  # Check if file was created AFTER the current latest
                latest = f_time
        print("The latest file is %s from %s" % (f, latest))
        f1 = files[0]
        f2 = files[1]
        cmd = "diff %s %s -yBw | grep ">" | sort -u" % (f1, f2)
        diff_out = subprocess.getoutput(cmd, shell=True)
        if diff_out:
            print("There's a diff - notify someone")
        elif not diff_out:
            print("No difference; how boring!")

    elif len(files) == 1:
        print("One file found - inspect it")

    else:
        print("There appears to be more than 2 enumall output files.  That shouldn't happen - please check it out.")


def subbrute(target):
    if not os.path.isfile("/opt/SubBrute/subbrute.py"):
        # TODO: Offer to install if not found at /opt/
        # TODO: Offer to let user define custom location (low priority)
        print("Subbrute.py not found, skipping.")
    else:
        subbrute_out = subprocess.getoutput("python /opt/SubBrute/subbrute.py %s" % target)
        print(subbrute_out)


if __name__ == "__main__":
    main()



# Resolve to IP(s)
# out = subprocess.getoutput("host %s" % target)
# Find IP(s) in output
# ips = re.findall( r'[0-9]+(?:\.[0-9]+){3}', out)