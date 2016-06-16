#!/usr/bin/env python3

"""
    submarine aggregates some existing tools for subdomain discovery in order to automate
    the time-consuming process of data collection on domains.  The script should be called with a single
    argument, indicating the target domain.

    Example:
        python3 submarine.py -t yahoo.com -a

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
     - VirusTotal API Call
     - SSL Certificate Inspection for Alt. Names (thx to ‎@bbuerhaus for help with this)

    # Future Improvements: Use Py3.5's asyncio feature set to make this all quicker
"""

import argparse
import os
import re
import socket
import subprocess
import sys
import urllib.parse
import urllib.request

import requests
from OpenSSL import SSL
from ndg.httpsclient.subj_alt_name import SubjectAltName
from pyasn1.codec.der import decoder as der_decoder

__author__ = "C. Joel Parsons (aka; 0rigen)"

__email__ = "0rigen@0rigen.net"
__version__ = "1.0"


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
     Note that b/c of how recon-ng names the files, the oldest file should always be found first,
     which this code depends on.  If this changes, the functions will need to be adjusted.

    :param target: The target site
    :return: list of target .lst files
    '''
    colors = bcolors
    target_files = []

    for root, dirs, files in os.walk('%s/' % target):
        for file in files:
            name = os.path.basename(file)
            if target in name:  # Found a file for my target
                if ".lst" in name:  # Found a list file
                    target_files.append(file)
    print(colors.OKBLUE + "[+] Found existing recon-ng output for this target." + colors.ENDC)
    return target_files


def updateMaster(new_file, target):
    '''
    Updates the master file named [target]_master wihtin the [target]/ directory.

    :param new_file: The consolidated list of subdomains to add to the master record.  Parameter
        must be the full path as in "target.com/new_target_file.txt"
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

    # Remove Duplicates using intermediate file
    sort_cmd = "sort %s/%s -u > %s/temp.txt" % (target, master_file, target)
    merge_cmd = "cat %s/temp.txt > %s/%s" % (target, target, master_file)
    rm_cmd = "rm %s/temp.txt" % target
    subprocess.call(sort_cmd, shell=True)  # Call sort with unique flag to filter dupes
    subprocess.call(merge_cmd, shell=True)  # Put the unique list back into master
    subprocess.call(rm_cmd, shell=True)  # Remove that temporary file

    print("[*] Master List Updated for %s" % target)


def main():
    color = bcolors

    # Check that I have the permissions to run (I should be sudo'd or root'd)
    if os.access("/usr/share/recon-ng/", os.W_OK):
        print(color.OKGREEN + "[+] recon-ng found and accessible." + color.ENDC)
    else:
        print(
            color.FAIL + "[!] You don't have sufficient permissions to run this script OR recon-ng is not installed at /usr/share/recon-ng." + color.ENDC)
        sys.exit(1)

    # Resolve command line arguments
    try:

        # Get Opts
        parser = argparse.ArgumentParser()
        parser.add_argument("-t", "--target", help="The target domain")
        parser.add_argument("-e", help="Perform enumall.sh enumeration via recon-ng", action="store_true")
        parser.add_argument("-s", help="Perform SubBrute.py enumeration", action="store_true")
        parser.add_argument("-c", help="Perform SSL Certificate Alt. name enumeration", action="store_true")
        parser.add_argument("-v", help="Perform VirusTotal API Enumeration", action="store_true")
        parser.add_argument("-a", help="Perform ALL checks.", action="store_true")
        args = parser.parse_args()
        target = args.target

        if args.a == False and args.v == False and args.c == False and args.s == False and args.e == False:
            print(color.FAIL + "[!] Bro, you gotta choose at least one enumeration technique!" + color.ENDC)
            sys.exit(2)

        print('''
               ___|          |                             _)
             \___ \\   |   |  __ \\   __ `__ \\    _` |   __|  |  __ \\    _ \\
                   |  |   |  |   |  |   |   |  (   |  |     |  |   |   __/
             _____/  \\__,_| _.__/  _|  _|  _| \\__,_| _|    _| _|  _| \\___|
        ''')
        print(color.OKGREEN + ("[+] Targeting %s" % target) + color.ENDC)
    except:
        print(color.FAIL + "[!] Error parsing arguments!" + color.ENDC)
        sys.exit(2)

    # Check to see if a folder already exists for that target
    if os.path.exists("%s/" % target):  # It does
        print(color.OKGREEN + "[+] I already have data for this target; files will be updated." + color.ENDC)
    else:  # It doesn't
        print(color.OKGREEN + "[+] New Target!  Creating a home for the data..." + color.ENDC)
        try:
            subprocess.call(["mkdir", target])  # Create it
        except:
            print(color.FAIL + "[!] Something went wrong creating the directory.  Permissions?" + color.ENDC)
            sys.exit(1)

    ###################
    # Main Call Block #
    ###################
    # Call subbrute.py - This is launched first, if selected, since it takes FO-EVAH
    if args.s or args.a:
        subbrute(target)

    # Call enumall.sh
    if args.e or args.a:
        enumall(target)
        subprocess.call("rm *.resource", shell=True)  # Get rid of the generated .resource files
        print("[+] Resource Files Removed.  Operations Complete.  Enjoy!")

    # Call VirusTotal API
    if args.v or args.a:
        virusTotal(target)

    # Inspect Certs of target
    if args.c or args.a:
        alt_names = []
        target_ips = resolveIP(target)
        for ip in target_ips:
            print(color.OKBLUE + ("[+] Target has IP %s.. Checking the cert on that IP" % ip) + color.ENDC)
            alt_names.append(getCertAltNames(ip))

        # Put alt names into temp file and then merge into the Master
        # TODO: This should really move to the getSubAltName() function to keep organized by functionality
        if alt_names:
            subprocess.call("touch temp.txt", shell=True)
            with open('temp.txt', 'w') as f:
                for item in alt_names:
                    f.write(''.join(item))
                    f.write("\n")
            updateMaster('temp.txt', target)
            subprocess.call("rm temp.txt", shell=True)
        else:
            print("[-] No AltNames to write.")

    # Resolve Hosts
    print("[+] Resolving discovered hosts")
    cmd = "python3 resolver.py %s/%s_master.txt %s/%s_IP.txt" % (target, target, target, target)
    subprocess.call(cmd, shell=True)


def enumall(target):
    '''
    Uses the enumall.sh script and subsequent calls to recon-ng to perform sub-domain discovery

    :param target: The target domain
    :return: None
    '''
    color = bcolors
    # The call...
    enum_p = subprocess.Popen(["./enumall.sh", target])
    enum_p.communicate()

    # Begin file processing by grabbing the new output
    mv_cmd = ("mv /usr/share/recon-ng/*%s*.lst %s/" % (target, target))  # Just build the command...
    subprocess.call(mv_cmd, shell=True)  # Move any new .lst files containing [target] into current directory
    files = findFile(target)  # Get all target-relevant .lst files

    latest = 1465820000.0  # Establish a base time for comparison.  Arbitrary old time.

    if not files:  # Nothing to process
        print(color.WARNING + "[!] No new enumall output files to process...That's odd." + color.ENDC)

    elif len(files) == 2:  # Multiple files exist
        for f in files:
            file_path = ("%s/%s" % (target, f))
            f_time = os.path.getctime(file_path)  # Get timestamp of file
            if f_time > latest:  # Check if file was created AFTER the current latest
                latest = f_time

        f1 = files[0]
        f2 = files[1]

        cmd = "diff %s %s -yBw | grep '>' | sort -u" % (f1, f2)
        diff_out = subprocess.getoutput(cmd)

        if diff_out:
            print(color.OKGREEN + "[+] There are new entries!" + color.ENDC)
            merge_cmd = ("cat %s/%s >> %s/%s" % (target, files[0], target, files[1]))
            merge_p = subprocess.Popen(merge_cmd, shell=True)  # Create single appended file
            merge_p.communicate()
            full_path = "%s/%s" % (target, files[1])
            updateMaster(full_path, target)  # Update the master file

        elif not diff_out:
            print(color.OKBLUE + "[+] No new entries... how boring!" + color.ENDC)

    elif len(files) == 1:
        print(
            color.OKBLUE + "[+] One file found - Either you're re-running this too soon, or this is a new target." + color.ENDC)
        full_path = "%s/%s" % (target, files[0])
        updateMaster(full_path,
                     target)  # Send the single file to updateMaster in order to create the Master from this source

    else:
        print(
            color.WARNING + "[!] There appears to be more than 2 enumall output files.  That shouldn't happen - please check it out." + ENDC)

    # Processing complete.  No matter what happened, we have all the data in a master file now,
    # so let's delete the oldest .lst file - it's not necessary any more.
    try:
        if len(files) == 2:
            rm_cmd = ("rm %s/%s" % (target, files[0]))
            subprocess.call(rm_cmd, shell=True)
    except:
        print(
            color.WARNING + "[!] Unable to remove old .lst file - please get rid of that or it'll bork me up!" + color.ENDC)


def subbrute(target):
    '''
    Uses the subbrute.py script from TheRook to brute force subdomains.
    This, by far, takes the longest, so we should launch it first, in the background.

    :param target:  The target domain
    :return: None
    '''
    # TODO: If target is specified just as target.com, I'll need to add a www. or http specifier here, temporarily
    colors = bcolors
    if not os.path.isfile("/opt/SubBrute/subbrute.py"):
        print(colors.FAIL + "[!] Subbrute.py not found." + colors.ENDC)
    else:
        print(colors.OKBLUE + "[*] Beginning subbrute method...This'll take awhile" + colors.ENDC)

        the_log = ("%s/subbrute_log.txt" % target)

        i = 0
        with open(the_log, 'w') as f:

            brute_p = subprocess.Popen(["nohup", "python", "/opt/SubBrute/subbrute.py", target], stdout=f,
                                      stderr=subprocess.STDOUT)
            print(
                colors.OKBLUE + ("[*] subbrute.py launched in the background with PID %s" % brute_p.pid) + colors.ENDC)

        with open(the_log, 'r') as f:  # Count the resulting discoveries
            for line in f:
                i += 1

        print(colors.OKGREEN + ("[*] Discovered %d subdomains through subbrute.py" % i) + colors.ENDC)
        # After it completes, update the master file
        updateMaster(the_log, target)


def virusTotal(target):
    '''
    Calls the VirusTotal API to do a subdomain search over the web.  There needs to be
    an API key for this to work.  The key should be placed in a single line text file named
    virus_total.key in the same directory as submarine.py

    Lesson Learned:  requests > urllib

    :param target:  The target domain
    :return: None
    '''
    colors = bcolors
    # Get API key
    key = ""
    try:
        keyFile = open('virus_total.key', 'r')
        key = keyFile.readline().rstrip()
    except:
        print(colors.FAIL + "[!] Error reading VirusTotal Key File, virus_total.key" + colors.ENDC)

    print("[*] Calling VirusTotal... ring ring...")

    url = "https://www.virustotal.com/vtapi/v2/domain/report"  # API url
    parameters = {"domain": target, "apikey": key}
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
    print(colors.OKBLUE + ("[*] %d subdomains discovered through VirusTotal API" % i) + colors.ENDC)
    # Add anything we discovered to the master list
    updateMaster(the_log, target)


###########################################################################
# Block for SSL Cert Inspection                                           #
# Big thanks to Brett Buerhaus of http://mrzioto.com/ for help with this  #
###########################################################################

def getCertAltNames(ipAddr, port=443):
    '''
    Connects to the target domain and inspects the cert for alternate
    names that the cert applies to via get_subj_alt_name()

    :param ipAddr: IP of the domain
    :param port: Port, almost always 443
    :return: List of alt names
    '''
    colors = bcolors
    context = SSL.Context(SSL.TLSv1_METHOD)
    context.set_options(SSL.OP_NO_SSLv2)
    context.set_verify(SSL.VERIFY_NONE, callback)
    sock = socket.socket()

    try:  # Initiate the connection
        ssl_sock = SSL.Connection(context, sock)
        sock.settimeout(0.5)
        ssl_sock.connect((str(ipAddr), port))
    except:
        print(colors.WARNING + "[!] Error connecting to target via SSL" + colors.ENDC)
        return False

    try:  # Perform the handshake

        sock.settimeout(None)
        ssl_sock.do_handshake()

        # get cert
        cert = ssl_sock.get_peer_certificate()
        name = cert.get_subject().commonName

        # try to save all cn/alt names
        try:
            alt = getSubAltName(cert)
            print(colors.OKBLUE + ("[*] Found alt names in cert for %d" % ipAddr) + colors.ENDC)
            return alt
        except:
            # Failed or nothing found
            print("[-] No Alt. names present in certificate.")
            return [name]

    except:
        print(colors.FAIL + "[!] Error connecting for Cert Inspection." + colors.ENDC)
        return False


def getSubAltName(peer_cert):
    '''
    Performs inspection of the SSL cert

    :param peer_cert:  The cert to inspect
    :return: dns_name - list of names found
    '''
    dns_name = []
    general_names = SubjectAltName()

    for i in range(peer_cert.get_extension_count()):
        extension = peer_cert.get_extension(i)
        extension_name = extension.get_short_name()
        if extension_name == "subjectAltName":
            extension_data = extension.get_data()
            decoded_data = der_decoder.decode(extension_data, asn1Spec=general_names)

            for name in decoded_data:
                if isinstance(name, SubjectAltName):
                    for entry in range(len(name)):
                        component = name.getComponentByPosition(entry)
                        dns_name.append(str(component.getComponent()))
    return dns_name


def callback(conn, cert, errno, depth, result):
    if depth == 0 and (errno == 9 or errno == 10):
        return False
    return True


def resolveIP(target):
    out = subprocess.getoutput("host %s" % target)
    # Find IP(s) in output
    ips = re.findall(r'[0-9]+(?:\.[0-9]+){3}', out)
    return ips


if __name__ == "__main__":
    main()
