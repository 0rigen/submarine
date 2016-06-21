'''
Watchman for detecting and notifying about newly discovered subdomains and IP Addresses


Cronjob, run early in the morning
 - Store list of known targets; if a new one is found (doesn't exist in known list), create new entry and copy over the Master file
 - diff all new target master lists with the stored ones, record any additions, ">"
 - Log or email to root the organized additions
 - Special Case: do not log ALL additions of new target, just say "Hey new target showed up, gj!"
