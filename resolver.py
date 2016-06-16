import sys, os
import subprocess
import re

if not sys.argv[1]:
    print("[!] You didn't supply an input file!")
    sys.exit(1)
if not sys.argv[2]:
    print("[!] You didn't supply an output file!")
    sys.exit(1)

if not os.path.isfile(sys.argv[1]):
    print("[!] That input file doesn't exist.")
if not os.path.isfile(sys.argv[2]):
    print("[-] Output file doesn't exist...creating it.")
    cmd = "touch %s" % sys.argv[2]
    subprocess.call(cmd, shell=True)

in_file = sys.argv[1]
out_file = sys.argv[2]

print("[*] Finding IPs for your hosts...")
with open(in_file, 'r') as i:
    contents = i.readlines()
    with open(out_file, 'w') as o:
        for line in contents:
            cmd = ("host %s" % line)
            sub_out = subprocess.getoutput(cmd)
            ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', sub_out)

            for item in ip:
                o.write("%s %s\n" % (line.rstrip(), item.rstrip()))
                # print("%s %s" % (line.rstrip(), item.rstrip()))

print("[+] Hosts resolved.  Output written to %s" % out_file)
