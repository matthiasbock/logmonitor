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

def matchRule2(line):
	if line == "test":
		return "2019-10-13 20:23:27 1iNLn5-0003SK-Ck H=testdomain.de [12.145.178.190] X=TLS1.2:ECDHE_RSA_AES_128_GCM_SHA256:128 CV=no F=<waldokjsckjg@losefatplans.co> rejected after DATA: Message rejected as spam."
	line = line.lower()
	if (line.find("rejected after data") > -1) and (line.find("spam") > -1):
		a = line.find("[")
		b = line.find("]")
		return line[a+1:b]
	return None

rules = [
	matchRule1,
	matchRule2
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
	date = subprocess.Popen(["date", "+%Y-%m-%d %H:%M:%S"], stdout=subprocess.PIPE, encoding="utf8").communicate()[0].strip()
	f = open(logfile, "a")
	f.write(date + " f2b-exim.py: " + s + "\n")
	f.close()


#
# Ban a certain IP from contacting our Exim again (typically for 24h)
#
def ban(ip):
	if (ip == "37.120.163.112"):
		print("Not banning whitelisted IP 37.120.163.112 (interoberlin.de).")
		log("Not banning whitelisted IP 37.120.163.112 (interoberlin.de).")
		return
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
	['tail', '-fn150', logfile],
	stdout=subprocess.PIPE,
	stderr=subprocess.PIPE,
	encoding='utf8'
	)

while True:
	line = f.stdout.readline()
	print(line.strip())
	evaluate(line)

