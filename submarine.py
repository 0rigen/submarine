#!/usr/bin/env python3

"""
    submarine aggregates some existing tools for subdomain discovery in order to automate
    the time-consuming process of data collection on domains.  The script should be called with a single
    argument, indicating the target domain.

    Example:
        python3 submarine.py yahoo.com

    Each target will have its data stored in a directory by that domain's name.  These directories are
    created as sub-directories to wherever this script lives.  A master list of subdomains is maintained
    in a file called "[target]_master.txt" within that directory, along with other working files.

    Directory Structure:
    submarine.py
        |__ yahoo.com
                |___ yahoo.com_master.txt
                |___ workingfile
                |___ workingfile
        |__ google.com
                |___ google.com_master.txt
                |___ workingfile
                |___ workingfile

    Techniques Implemented So Far:
     - enumall.sh (jhaddix) / recon-ng (LaNMaSteR53)
     - subbrute.py (TheRook)
     - VirusTotal API

    Techniques To Be Added:
    * Certificate Inspection
    * DNSRecon

    # Future Improvements: Use Py3.5's asyncio feature set to make this all quicker
"""

import os
import subprocess
import sys
import requests
import urllib.parse
import urllib.request
#from termcolor import colored


__author__ = "C. Joel Parsons (aka; 0rigen)"
__copyright__ = "Copyright 2007, The Cogent Project"

__license__ = "GPL"
__version__ = "3.0"
__maintainer__ = "0rigen"
__email__ = "0rigen@0rigen.net"
__status__ = "Prototype"


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def findFile(target):
    '''
     Note that b/c of how recon-ng names the files, the odlest file should always be found first,
     which my code depends upon.  If this changes, the functions will need to be adjusted.

    :param target: The target site
    :return: list of target .lst files
    '''
    target_files = []

    for root, dirs, files in os.walk('%s/' % target):
        for file in files:
            name = os.path.basename(file)
            if target in name:  # Found a file for my target
                if ".lst" in name:  # Found a list file
                    target_files.append(file)
    return target_files


def updateMaster(new_file, target):
    '''
    Updates the master file named [target]_master wihtin the [target]/ directory.

    :param new_file: The consolidated list of subdomains to add to the master record
    :param target: The target site
    :return: None
    '''
    # Check to ensure that I don't need to change directories at this point.. I may need to chdir into the target dir

    master_file = ("%s_master.txt" % target)

    if not os.path.isfile(target + "/" + master_file):  # If there is no master list, create one
        create_master_cmd = ("touch %s/%s_master.txt" % (target, target))
        subprocess.Popen(create_master_cmd, shell=True)

    master_cmd = "cat %s | sort -u >> %s/%s" % (new_file, target, master_file)  # Append into the master
    subprocess.call(master_cmd, shell=True)
    # TODO: Filter out duplicates, ensure unique entries only
    print("[*] Master List Updated for %s" % target)


def main():
    # Resolve command line target
    try:
        target = sys.argv[1]
        print("[+] Targeting %s" % target)
    except:
        print("[!] I couldn't understand the target!")
        sys.exit(1)

    # Check to see if a folder already exists for that target
    if os.path.exists("%s/" % target):  # It does
        print("[+] I already have data for this target; files will be updated.")
    else:  # It doesn't
        print("[+] New Target!  Creating a home for the data...")
        try:
            subprocess.call(["mkdir", target])  # Create it
            # TODO: Create master subs file
        except:
            print("[!] Something went wrong creating the directory.  Permissions?")
            sys.exit(1)

    ##########################
    # Begin domain finding
    ##########################
    enumall(target)
    virusTotal(target)
    subbrute(target)

    subprocess.call(["rm","*.resource"])
    print("[+] Resource Files Removed.  Operations Complete.  Enjoy!")


def enumall(target):
    '''
    Uses the enumall.sh script and subsequent calls to recon-ng to perform sub-domain discovery

    :param target: The target domain
    :return: None
    '''
    # The call...
    enum_p = subprocess.Popen(["./enumall.sh", target])
    enum_p.communicate()

    # Begin file processing by grabbing the new output
    cmd = ("mv /usr/share/recon-ng/*.lst %s/" % target)  # Just build the command...
    subprocess.call(cmd, shell=True)  # Move any new .lst files into current directory
    files = findFile(target)  # Get all target-relevant .lst files

    latest = 1465820000.0  # Establish a base time for comparison.  Arbitrary old time.

    if not files:  # Nothing to process
        print("[!] No new enumall output files to process...That's odd.")

    elif len(files) == 2:  # Multiple files exist
        for f in files:
            file_path = ("%s/%s" % (target,f))
            f_time = os.path.getctime(file_path)  # Get timestamp of file
            if f_time > latest:  # Check if file was created AFTER the current latest
                latest = f_time

        f1 = files[0]
        f2 = files[1]

        cmd = "diff %s %s -yBw | grep '>' | sort -u" % (f1, f2)
        diff_out = subprocess.getoutput(cmd)

        if diff_out:
            print("[+] There are new entries!")

            merge_cmd = ("cat %s/%s >> %s" % (target, files[0], files[1]))
            merge_p = subprocess.Popen(merge_cmd, shell=True)  # Create single appended file
            merge_p.communicate()
            updateMaster(files[1], target)  # Update the master file

        elif not diff_out:
            print("[+] No new entries... how boring!")
            # I'm not going to call updateMaster and attempt any updates unless there was a change
            # in the enumall output itself.  Why bother?

    elif len(files) == 1:
        print("[+] One file found - Either you're re-running this too soon, or this is a new target.")
        updateMaster(files[0],
                     target)  # Send the single file to updateMaster in order to create the Master from this source

    else:
        print("[!] There appears to be more than 2 enumall output files.  That shouldn't happen - please check it out.")

    # Processing complete.  No matter what happened, we have all the data in a master file now,
    # so let's delete the oldest .lst file - it's not necessary any more.
    try:
        rm_cmd=("rm %s/%s" % (target, files[0]))
        subprocess.call(rm_cmd, shell=True)
    except:
        print("[!] Unable to remove old .lst file - please get rid of that or it'll bork me up!")


def subbrute(target):
    '''
    Uses the subbrute.py script from TheRook to brute force subdomains.
    This, by far, takes the longest, so we should do it last.

    :param target:  The target domain
    :return: None
    '''
    if not os.path.isfile("/opt/SubBrute/subbrute.py"):
        print("[!] Subbrute.py not found, skipping.")
    else:
        print("[*] Beginning subbrute method...This'll take awhile")

        the_log = ("%s/subbrute_log.txt" % target)

        i = 0
        with open(the_log, 'w') as f:
            brute_p = subprocess.call(["nohup", "python", "/opt/SubBrute/subbrute.py", target], stdout=f, stderr=subprocess.STDOUT)
            #brute_p.communicate()

        with open(the_log, 'r') as f:  # Count the resulting discoveries
            for line in f:
                i += 1

        print("[*] Discovered %d subdomains through subbrute.py" % i)
        # After it completes, update the master file
        updateMaster(the_log, target)


def virusTotal(target):
    '''
    Calls the VirusTotal API to do a subdomain search over the web.  There needs to be
    an API key for this to work.

    Lesson Learned:  requests > urllib

    :param target:  The target domain
    :return: None
    '''
    # Get API key
    key = ""
    try:
        keyFile = open('virus_total.key', 'r')
        key = keyFile.readline().rstrip()
    except:
        print("[!] Error reading VirusTotal Key File.")

    print("[*] Calling VirusTotal... ring ring...")

    url = "https://www.virustotal.com/vtapi/v2/domain/report"  # API url
    parameters = {"domain": target, "apikey": key}  # API Paramater construction
    response = requests.get('%s?%s' % (url, urllib.parse.urlencode(parameters))).json()  # Read the response

    # Access and save the "subdomains" field, that's all we want
    subs = response['subdomains']

    the_log = ("%s/virustotal_log.txt" % target)

    if not os.path.isfile("%s/virustotal_log.txt"):  # If the log doesn't exist... create it
        subprocess.call(["touch", the_log])

    # Write the subs to the file logi
    i = 0
    with open(the_log, 'w') as f:
        for item in subs:
            f.write(item)
            i += 1
            f.write("\n")
    print("[*] %d subdomains discovered through VirusTotal API" % i)
    # Add anything we discovered to the master list
    updateMaster(the_log, target)

if __name__ == "__main__":
    main()

    ############# Notes Graveyard ##########################

    # Resolve to IP(s)
    # out = subprocess.getoutput("host %s" % target)
    # Find IP(s) in output
    # ips = re.findall( r'[0-9]+(?:\.[0-9]+){3}', out)
