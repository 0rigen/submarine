workspaces select yahoo.com06_12_2016
set TIMEOUT 100
use recon/domains-hosts/baidu_site
set SOURCE yahoo.com
run
use recon/domains-hosts/bing_domain_web
set SOURCE yahoo.com
run
use recon/domains-hosts/google_site_web
set SOURCE yahoo.com
run
use recon/domains-hosts/netcraft
set SOURCE yahoo.com
run
use recon/domains-hosts/yahoo_domain
set SOURCE yahoo.com
run
use recon/domains-hosts/shodan_hostname
set SOURCE yahoo.com
run
use recon/domains-hosts/brute_hosts
set WORDLIST /usr/share/recon-ng/data/sorted_knock_dnsrecon_fierce_recon-ng.txt
set SOURCE yahoo.com
run
use recon/netblocks-companies/whois_orgs
set SOURCE yahoo.com
run
use recon/hosts-hosts/resolve
set SOURCE yahoo.com
run
use reporting/csv
set FILENAME yahoo.com06_12_2016.csv
run
use reporting/list
set FILENAME yahoo.com06_12_2016.lst
set COLUMN host
run
exit
