#!/usr/bin/python3
#
# This script monitors the exim logfile
# and bans IPs when detecting suspicious activities
#

import subprocess
import re

logfile = "/var/log/exim4/mainlog"


#
# Ban rules
#
def matchRule1(line):
	if line == "test":
		return "2019-10-22 01:00:18 plain_server authenticator failed for (hosting-by.directwebhost.org.) [45.227.253.139]: 535 Incorrect authentication data (set_id=postmaster@testdomain.net)"
	if line.find("535 Incorrect authentication data") > -1:
		a = line.find("[")
		b = line.find("]")
		return line[a+1:b]
	return None

rules = [
	matchRule1
	]

#
# Test filter rules
#
print("Performing positive rule tests...")
i = 1
for rule in rules:
	line = rule("test")
	if rule(line) is None:
		print("Rule {:d}: FAIL".format(i))
	else:
		print("Rule {:d}: PASS".format(i))	

print("Performing negative rule tests...")
test_negative = "2019-10-23 00:24:29 Start queue run: pid=12335"
i = 1
for rule in rules:
	if rule(test_negative) is None:
		print("Rule {:d}: PASS".format(i))
	else:
		print("Rule {:d}: FAIL".format(i))
	i += 1

#
# Append a line to the logfile
#
def log(s):
	s = s.strip()
	f = open(logfile, "a")
	f.write(s + "\n")
	f.close()


#
# Ban a certain IP from contacting our Exim again (typically for 24h)
#
def ban(ip):
	print("Banning IP {:s} for 24h ...".format(ip))
	subprocess.Popen(["fail2ban-client", "set", "exim", "banip", ip]).wait()
	log("IP {:s} banned for 24h.".format(ip))


#
# Evaluate the new log line: Does it match a ban rule?
#
def evaluate(line):
	for rule in rules:
		result = rule(line)
		if result is None:
			continue
		ban(result)
		break


print("Monitoring {:s} ... Press Ctrl+C to cancel.".format(logfile))
f = subprocess.Popen(
	['tail', '-fn50', logfile],
	stdout=subprocess.PIPE,
	stderr=subprocess.PIPE,
	encoding='utf8'
	)

while True:
	line = f.stdout.readline()
	print(line.strip())
	evaluate(line)

