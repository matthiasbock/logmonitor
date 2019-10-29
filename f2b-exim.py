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

def matchRule3(line):
	if line == "test":
		return "2019-10-21 03:04:32 H=([193.32.160.150]) [193.32.160.150] F=<dkedoeyo4nrapb0k@daipra.it> rejected RCPT <aazevedo@diybio.de>: X-Host-Lookup-Failed: Reverse DNS lookup failed for 193.32.160.150 (failed)"
	if line.find("X-Host-Lookup-Failed: Reverse DNS lookup failed") > -1:
		a = line.find("[")
		b = line.find("]")
		return line[a+1:b]
	return None

def matchRule4(line):
	if line == "test":
		return "2019-01-23 04:01:49 SMTP protocol synchronization error (input sent without waiting for greeting): rejected connection from H=ec2-34-200-230-3.compute-1.amazonaws.com [34.200.230.3] input="
	if line.find("SMTP protocol synchronization error (input sent without waiting for greeting)") > -1:
		a = line.find("[")
		b = line.find("]")
		return line[a+1:b]
	return None

def matchRule5(line):
	if line == "test":
		return "2019-10-22 12:07:31 H=(k9ZsfxBuX3) [171.78.142.150] F=<webmaster@testdomain.de> rejected RCPT <uknluk09@gmail.com>: relay not permitted"
	if (line.find("rejected RCPT") > -1) \
	and (line.find("relay not permitted") > -1):
		a = line.find("[")
		b = line.find("]")
		return line[a+1:b]
	return None

rules = [
	matchRule1,
	matchRule2,
	matchRule3,
	matchRule4,
	matchRule5
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


print("Setting bantime to 24h ...")
subprocess.Popen(["fail2ban-client", "set", "exim", "bantime", str(24*60*60)]).wait()

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

