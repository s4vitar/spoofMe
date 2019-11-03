#!/usr/bin/python
# coding: utf-8

# Autor: Marcelo Vázquez (aka s4vitar)

import re, shutil, tempfile, signal
import requests
import sys
import ssl
import os

from time import sleep

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

if len(sys.argv) != 4:
	print "\n" + bcolors.OKGREEN + "[" + bcolors.ENDC + bcolors.OKBLUE + "*" + bcolors.OKGREEN + "] Usage: python " + sys.argv[0] + " <area-code> <phone-number> <login-pin>\n" + bcolors.ENDC
	print bcolors.BOLD + "Example: python " + sys.argv[0] + " 34 XXXXXXXXX 1234\n" + bcolors.ENDC
	sys.exit(0)

def signal_handler(key, frame):
	print "\n\n[*] Exiting...\n"
	sys.exit(1)

signal = signal.signal(signal.SIGINT, signal_handler)

area_code = sys.argv[1]
phone_number = "+" + area_code + sys.argv[2]
login_pin = sys.argv[3]

url = 'https://www.spoofcard.com/login'
url_account = 'https://www.spoofcard.com/account'
url_settings = 'https://www.spoofcard.com/account/settings'
url_call_spoof = 'https://www.spoofcard.com/account/calls/create'
url_sms_spoof = 'https://www.spoofcard.com/account/two-way-sms/create'

def sed_inplace(filename, pattern, repl):

    pattern_compiled = re.compile(pattern)

    with tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp_file:
        with open(filename) as src_file:
            for line in src_file:
                tmp_file.write(pattern_compiled.sub(repl, line))

    shutil.copystat(filename, tmp_file.name)
    shutil.move(tmp_file.name, filename)

def sms_spoofing():
	destination_number = raw_input('\nDestination Number [+34XXXXXXXXX]: ')
	display_number = raw_input('\nDisplay Number [+34XXXXXXXXX]: ')
	message = raw_input('\nEnter message to display: ')

	sms_spoofing_data = {'body': message, 'destination_address': destination_number, 'source_address': display_number, 'tos_accepted': 'true', 'oneWay': 'true'}
	sms_spoofing_headers = {'accept-encoding': 'gzip, deflate, br', 'accept-language': 'es-ES,es;q=0.9,en;q=0.8', 'content-type': 'application/x-www-form-urlencoded', 'accept': 'application/json, text/plain, */*', 'x-requested-with': 'XMLHttpRequest'}

	r = session.post(url_sms_spoof, data=sms_spoofing_data, headers=sms_spoofing_headers, verify=False)

	print "\n[*] Message has been sent\n"

def call_spoofing():
	destination_number = raw_input('\nDestination Number [+34XXXXXXXXX]: ')
	display_number = raw_input('\nDisplay Number [+34XXXXXXXXX]: ')

	call_spoofing_data = {'destination_address': destination_number, 'display_address': display_number, 'event_type': 'outbound-call', 'plugins[background_noise][choice_index]': '9'}
	call_spoofing_headers = {'content-type': 'application/x-www-form-urlencoded; charset=UTF-8', 'accept': 'application/json, text/javascript, */*; q=0.01', 'x-requested-with': 'XMLHttpRequest'}

	r = session.post(url_call_spoof, data=call_spoofing_data, headers=call_spoofing_headers, verify=False)

	content_file = open("dial_response.txt", "w")
	content_file.write(r.content)
	content_file.close()

	sed_inplace('dial_response.txt', r'\,', '\n')

	dial_access_code = []

	with open('dial_response.txt') as f:
	        for lines in f:
				if re.search("access_code", lines):
					dial_access_code.append(lines.split(':')[1].split('"')[1])

	with open('dial_numbers.txt') as f:
		dial_numbers = [lines.rstrip('\n') for lines in f.readlines()]

	print '\n--------------------------------------------'

	for numbers in dial_numbers:
		print numbers

	print "\n------------------"
	print "Access-Code: %s |" % dial_access_code[0]
	print '--------------------------------------------\n'

	print "[*] Now call any of the numbers listed above [It is recommended to call the number +39 0356306566]"
	print "[*] Once done, you will need to enter the Access-Code provided above"
	print "[*] When finished, press <Enter> key to finish the program\n"

	raw_input("Press <Enter> to continue...")

	os.remove("dial_response.txt")
	session.close()

banner = "\n╱╱╱╱╱╱╱╱╱╱╱╱╱╭━┳━╮╭━╮\n"
banner += "╱╱╱╱╱╱╱╱╱╱╱╱╱┃╭┫┃╰╯┃┃\n"
banner += "╭━━┳━━┳━━┳━━┳╯╰┫╭╮╭╮┣━━╮\n"
banner += "┃━━┫╭╮┃╭╮┃╭╮┣╮╭┫┃┃┃┃┃┃━┫" + bcolors.WARNING + " (Owner Marcelo Vázquez - aka " + bcolors.ENDC + bcolors.OKBLUE + "s4vitar" + bcolors.ENDC + bcolors.WARNING + ")\n" + bcolors.ENDC
banner += "┣━━┃╰╯┃╰╯┃╰╯┃┃┃┃┃┃┃┃┃┃━┫\n"
banner += "╰━━┫╭━┻━━┻━━╯╰╯╰╯╰╯╰┻━━╯\n"
banner += "╱╱╱┃┃\n"
banner += "╱╱╱╰╯\n"

print banner

login = {'provider_type': 'phone', 'access_token': '', 'redirect_url': '', 'countrycode': area_code, 'phone_number': phone_number, 'login-pin': login_pin}

requests.packages.urllib3.disable_warnings()

print "\n" + bcolors.OKGREEN + "[" + bcolors.ENDC + bcolors.OKBLUE + "*" + bcolors.ENDC + bcolors.OKGREEN + "] Collecting data...\n" + bcolors.ENDC

session = requests.Session()
r = session.post(url, data=login, verify=False)

content_file = open("content_response.txt", "w")
content_file.write(r.content)
content_file.close()

with open('content_response.txt') as f:
	for lines in f:
		if re.search("incorrect", lines):
			print bcolors.OKGREEN + "[" + bcolors.ENDC + bcolors.OKBLUE + "*" + bcolors.ENDC + bcolors.OKGREEN + "] The data entered does not correspond to any account\n" + bcolors.ENDC
			print bcolors.OKGREEN + "[" + bcolors.ENDC + bcolors.OKBLUE + "*" + bcolors.ENDC + bcolors.OKGREEN + "] Please, create an account first at https://www.spoofcard.com\n" + bcolors.ENDC
			os.remove("content_response.txt")
			sys.exit(0)

os.remove("content_response.txt")

r = session.post(url_account, data=login, verify=False)

content_file = open("content_response.txt", "w")
content_file.write(r.content)
content_file.close()

with open('content_response.txt') as f:
        for lines in f:
                if re.search("credits_remaining", lines):
			total_credits = lines.split('>')[2].split('<')[0]


os.remove("content_response.txt")

r = session.post(url_settings, verify=False)

content_file = open("settings_response.txt", "w")
content_file.write(r.content)
content_file.close()

with open('settings_response.txt') as f:
        for lines in f:
                if re.search("first_name:", lines):
                        first_name = lines.split(':')[1].split('\'')[1]
		if re.search("last_name:", lines):
			last_name = lines.split(':')[1].split('\'')[1]
		if re.search("email:", lines):
			email = lines.split(':')[1].split('\'')[1]

os.remove("settings_response.txt")

print "*****************************"
print "Credits on Account: %s " % total_credits + '\n'
print "First name: %s" % first_name
print "Second name: %s" % last_name
print "Email: %s" % email
print "*****************************"

if total_credits == "0":
	print '\n' + bcolors.FAIL + "You have no credits available" + bcolors.ENDC + '\n'
	sys.exit(0)

print "\n     " + bcolors.WARNING + "[" + bcolors.ENDC + bcolors.HEADER + "MENU" + bcolors.ENDC + bcolors.WARNING + "]" + bcolors.ENDC
print "-----------------"
print "1. Call Spoofing"
print "2. SMS Spoofing"
print "0. Exit"
print "-----------------"

menu_option = raw_input("Choose option: ")

if menu_option == "1":
	call_spoofing()
elif menu_option == "2":
	sms_spoofing()
elif menu_option == "0":
	sys.exit(0)
else:
	print "\nInvalid Option\n"
