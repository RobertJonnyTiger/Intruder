#!/usr/bin/python3
"""
Description:
	This uses a single set of payloads_sets. It targets each payload position in turn, and places each payload into that position in turn.
	Positions that are not targeted for a given request are not affected - the position markers are removed and any enclosed text that appears between them in the template remains unchanged.
	This attack type is useful for fuzzing a number of request parameters individually for common vulnerabilities.
	The total number of requests generated in the attack is the product of the number of positions and the number of payloads_sets in the payload set.
"""
import argparse
import requests
import Burpee.burpee as burp
import re
import string
import urllib3
from   urllib.parse import urlparse
from bs4 import BeautifulSoup
from tabulate import tabulate
from core.colors import *
from itertools import combinations, product
from time import sleep

# Defines Parser:
parser = argparse.ArgumentParser(description = 'Intruder is a powerful tool for automating customized attacks against web applications. It can be used to automate all kinds of tasks that may arise during your testing.')
parser.add_argument('request_file', help = 'Request file with marked variables (POST or GET).')
parser.add_argument('-p --payloads_sets', help = 'Set or multiple sets of payloads_sets to run.', required =
True,
					nargs = '+', dest = 'payloads_sets')
parser.add_argument('-o', '--output', help = 'Name for the output file. (Default: output.txt)',
					dest = 'output_path',
					default = 'output.txt')
parser.add_argument('-s', '--sleep', help = 'Sets a sleep timer (in secs) between requests.', type = float)
parser.add_argument('-v', '--verbose', help = 'Verbose mode to show errors', action = 'store_true',
                    default = False)

# Args to be parsed:
args          = parser.parse_args()
delay         = args.sleep
output_path   = args.output_path
payloads_sets = args.payloads_sets
request_file  = args.request_file
verbose       = args.verbose

headers, POST_data = burp.parse_request(request_file)
METHOD             = burp.get_method_and_resource(request_file)[0]  # Sets METHOD (POST \ GET)

def main_menu() -> str:
	"""Main Menu that will prompt the user to choose the MARKER that will be used and attack type.
	Prints the MARKER and METHOD used."""
	global table, url
	choice = '0'

	# Welcome message and input for MARKER:
	print('%s%sWelcome to Intruder!%s' % (bold, underline, end))
	MARKER = input("%s %sWhat are the markers for the variables? (Default: '$')%s: " % (que, bold,
	                                                                                    end)) or '$'
	print(f"{info} %s%sMarker set to%s: '{MARKER}'" % (bold, underline, end))
	if MARKER in string.punctuation: MARKER = f'\{MARKER}'
	
	# After setting the MARKER, gets the vars from get_vars() using the MARKER as an arg:
	url, data_dict = get_vars(MARKER)
	
	# Prints Main-Menu, asks for user's choice:
	while choice == '0':
		print("%s%sPlease choose an attack-type to run ('q' to quit):%s" % (underline, yellow, end))
		print('%s Type %s1%s for %sSniper%s.' % (run, bold, end, bold, end))
		print('%s Type %s2%s for %sBattering-Ram%s.' % (run, bold, end, bold, end))
		print('%s Type %s3%s for %sPitchfork%s.' % (run, bold, end, bold, end))
		print('%s Type %s4%s for %sCluster-Bomb%s.' % (run, bold, end, bold, end))
		choice = input('%s %sType your choice%s: ' % (que, bold, end))
		# Options:
		if choice == '1':
			print("%s %sStarting Sniper Attack...%s" % (run, bold, end))
			table = sniper(url, data_dict)
			return table
		elif choice == '2':
			print("%s %sStarting Battering-Ram Attack...%s" % (run, bold, end))
			table = battering_ram(url, data_dict)
			return table
		elif choice == '3':
			print("%s %sStarting Pitchfork Attack...%s" % (run, bold, end))
			table = pitchfork(url, data_dict)
			return table
		elif choice == '4':
			print("%s %sStarting Clusterbomb Attack...%s" % (run, bold, end))
			table = clusterbomb(url, data_dict)
			return table
		elif choice == 'q':
			exit()
		else:
			print('%s %s%sInvalid choice.%s' % (bad, bold, red, end))
			choice = '0'

def get_vars(MARKER: str) -> (str, dict):
	"""Returns 2 variables depending on the request METHOD:
data_dict = The data dictionary that will be used with requests.
dest_url = Destination URL for the requests."""
	referer     = headers.get('Referer')  # URL Referer
	destination = burp.get_method_and_resource(request_file)[1]  # Where the referer sends the request to.
	local_base  = f"{urlparse(referer).scheme}://{urlparse(referer).netloc}"
	dest_url    = local_base + destination # Finalized destination URL.

	# Request Data\Params Builder. Depending on METHOD:
	if METHOD == 'POST':
		print(f'{info}%s%s Request Method%s: {METHOD}' % (bold, underline, end))
		parameters = POST_data.strip().split('&')
		data_dict = {}
		for f in parameters:
			data_dict[f.split('=')[0]] = f.split('=')[1].strip(f'{MARKER}')
	if METHOD == 'GET':
		print(f'{info} %s%sRequest Method%s: {METHOD}' % (bold, underline, end))
		parameters = burp.get_method_and_resource(request_file)[1].strip().split('?')[1]
		parameters = parameters.split('&')
		data_dict = {}
		for f in parameters:
			data_dict[f.split('=')[0]] = f.split('=')[1].strip(f'{MARKER}')
	return dest_url, data_dict

def sniper(dest_url: str, data_dict: dict) -> str:
	"""This uses a single set of payloads_sets. It targets each payload position in turn, and places each payload into that position in turn."""
	# Check amount of payloads_sets:
	if len(payloads_sets) >= 2:
		print(f"{bad} %s%sDetected multiple sets of payloads!%s" % (underline, bold, end))
		print(f"{info} %s%sSniper method takes only 1 payload set.%s First payload "
	                                  f"provided will "
	                                  "be used now." % (bold, yellow, end))
	# Builds payloads list:
	with open(payloads_sets[0]) as file:
		payloads = []
		for line in file.readlines(): payloads.append(line.strip()) # Appends payloads_sets from payloads_sets file.
		
	# For table usage:
	request_counter, position = 0, 0
	Request, Position, Payload, Status_Code, Content, Content_Length = [], [], [], [], [], []
	
	for key in data_dict:
		position += 1
		original_key = data_dict[key]    # Saves the original value of key to a variable.
		for payload in payloads:
			Request.append(request_counter); Position.append(position); Payload.append(payload)
			data_dict[key] = payload
			
			# Starts sending requests with payloads:
			try:
				request_counter += 1
				if METHOD == 'POST': response = requests.post(dest_url, headers = headers, data = data_dict)
				if METHOD == 'GET': response = requests.get(dest_url, headers = headers, params = data_dict)
				content = BeautifulSoup(response.content, "lxml").text
				Status_Code.append(response.status_code); Content.append(content); Content_Length.append(len(content))
			except Exception as error:
				print(f"\n{bad}%s%s Connection Refused%s (--verbose to check error)" % (bold, red, end))
				if verbose: print(f'%sError Message%s: {error}' % (underline, end))
				print(f'{tab}%sPayload%s: {data_dict[key]}' % (underline, end))
				print(f'{tab}%sPosition%s: {position}' % (underline, end))
				Status_Code.append('None'); Content.append('[X] Error'); Content_Length.append('None')
				pass
			data_dict[key] = original_key
			if delay: sleep(delay)
	Table = tabulate({
		'Request'       : Request,
		'Position'      : Position,
		'Payload'       : Payload,
		'Status Code'   : Status_Code,
		'Content'       : Content,
		'Content Length': Content_Length,
		}, headers = 'keys', tablefmt = 'psql', colalign = ('center', 'center'), disable_numparse=True)
	print(f"\n%s %s%sFinished Sniper attack on%s: {url}\n" % (good, underline, bold, end))
	print(Table)
	return Table

def battering_ram(dest_url: str, data_dict: dict) -> str:
	"""Allows only 1 payload, runs on ALL the marked positions in the same time. Prints results to stdout."""
	# Check amount of payloads_sets:
	if len(payloads_sets) >= 2:
		print(f"{bad} %s%sDetected multiple sets of payloads!%s" % (underline, bold, end))
		print(f"{info} %s%sBattering-Ram method takes only 1 payload set.%s First payload "
		      f"provided will "
		      "be used now." % (bold, yellow, end))
		
	# Builds payloads list:
	with open(payloads_sets[0]) as file:
		payloads = []
		for line in file.readlines(): payloads.append(line.strip())  # Appends payloads_sets from payloads_sets file.
		
	# For table usage:
	request_counter = 0
	Request, Payload, Status_Code, Content, Content_Length = [], [], [], [], []
	for payload in payloads:
		for key in data_dict:
			data_dict[key] = payload
		# Starts sending requests with payloads:
		try:
			request_counter += 1
			Request.append(request_counter); Payload.append(payload)
			if METHOD == 'POST': response = requests.post(dest_url, headers = headers, data = data_dict)
			if METHOD == 'GET': response = requests.get(dest_url, headers = headers, params = data_dict)
			content = BeautifulSoup(response.content, "lxml").text
			Status_Code.append(response.status_code); Content.append(content); Content_Length.append(len(content))
		except Exception as error:
			print(f"\n{bad}%s%s Connection Refused%s (--verbose to check error)" % (bold, red, end))
			if verbose: print(f'%sError Message%s: {error}' % (underline, end))
			print(f'{tab}%sPayload%s: {data_dict[key]}' % (underline, end))
			Status_Code.append('None'); Content.append('[X] Error'); Content_Length.append('None')
			pass
		if delay: sleep(delay)
	Table = tabulate({
		'Request'       : Request,
		'Payload'       : Payload,
		'Status Code'   : Status_Code,
		'Content'       : Content,
		'Content Length': Content_Length,
		}, headers = 'keys', tablefmt = 'psql', colalign = ('center', 'center'), disable_numparse = True)
	print(f"\n%s %s%sFinished Battering-Ram attack on%s: {url}\n" % (good, underline, bold, end))
	print(Table)
	return Table

def pitchfork(dest_url: str, data_dict: dict) -> str:
	"""Uses multiple payload sets. There is a different payload set for each defined position (up to a
	maximum of 20). The attack iterates through all payload sets simultaneously, and places one payload
	into each defined position. Prints results to stdout."""
	# Creates a list of lists of payloads [[p1, p2, p3], [p21, p22, p23]...]
	payloads_list_of_lists = []
	for Set in payloads_sets:
		with open(Set) as Set:
			payloads = []
			for line in Set.readlines(): payloads.append(line.strip())
			payloads_list_of_lists.append(payloads)
	
	# For table usage:
	request_counter = 0
	Request, Payloads, Status_Code, Content, Content_Length = [], [], [], [], []
	
	# Creates data dict with current payloads:
	for cur_values in zip(*payloads_list_of_lists):
		named_values = zip(data_dict.keys(), cur_values)
		payloads_for_request = dict(named_values)
		
		# Starts sending requests for each data dict created:
		try:
			request_counter += 1
			Request.append(request_counter); Payloads.append(payloads_for_request)
			if METHOD == 'POST': response = requests.post(dest_url, headers = headers, data = data_dict)
			if METHOD == 'GET': response = requests.get(dest_url, headers = headers, params = data_dict)
			content = BeautifulSoup(response.content, "lxml").text
			Status_Code.append(response.status_code); Content.append(content); Content_Length.append(len(content))
		except Exception as error:
			print(f"\n{bad}%s%s Connection Refused%s (--verbose to check error)" % (bold, red, end))
			if verbose: print(f'%sError Message%s: {error}' % (underline, end))
			print(f'{tab}%sPayloads%s: {payloads_for_request}' % (underline, end))
			Status_Code.append('None');	Content.append('[X] Error'); Content_Length.append('None')
			pass
		if delay: sleep(delay)  # If sleep argument provided.
	Table = tabulate({
			'Request'       : Request,
			'Payloads'       : Payloads,
			'Status Code'   : Status_Code,
			'Content'       : Content,
			'Content Length': Content_Length,
			}, headers = 'keys', tablefmt = 'psql', colalign = ('center', 'center'), disable_numparse = True)
	print(f"\n%s %s%sFinished Pitchfork attack on%s: {url}" % (good, underline, bold, end))
	print(Table)
	return Table
	
def clusterbomb(dest_url: str, data_dict: dict) -> str:
	"""Allows up to 20 payloads, 1 payload for each position marked. Tries all possible combinations of
    payloads per position."""
	# Creates a list of lists of payloads [[p1, p2, p3], [p21, p22, p23]...]
	payloads_list_of_lists = []
	for Set in payloads_sets:
		with open(Set) as Set:
			payloads = []
			for line in Set.readlines(): payloads.append(line.strip())
			payloads_list_of_lists.append(payloads)
		
	# For table usage:
	request_counter = 0
	Request, Payloads, Status_Code, Content, Content_Length = [], [], [], [], []
	
	# Creates data dict with current payloads:
	combs_list = list(product(*payloads_list_of_lists))
	for i in combs_list:
		named_values = zip(data_dict.keys(), i)
		payloads_for_request = dict(named_values)
		
		# Start sending requests for each data dict created:
		try:
			request_counter += 1
			Request.append(request_counter); Payloads.append(payloads_for_request)
			if METHOD == 'POST': response = requests.post(dest_url, headers = headers, data = data_dict)
			if METHOD == 'GET': response = requests.get(dest_url, headers = headers, params = data_dict)
			content = BeautifulSoup(response.content, "lxml").text
			Status_Code.append(response.status_code); Content.append(content); Content_Length.append(len(content))
		except Exception as error:
			print(f"\n{bad}%s%s Connection Refused%s (--verbose to check error)" % (bold, red, end))
			if verbose: print(f'%sError Message%s: {error}' % (underline, end))
			print(f'{tab}%sPayloads%s: {payloads_for_request}' % (underline, end))
			Status_Code.append('None');	Content.append('[X] Error'); Content_Length.append('None')
			pass
		if delay: sleep(delay)
	
	Table = tabulate({
			'Request'       : Request,
			'Payloads'       : Payloads,
			'Status Code'   : Status_Code,
			'Content'       : Content,
			'Content Length': Content_Length,
			}, headers = 'keys', tablefmt = 'psql', colalign = ('center', 'center'), disable_numparse = True)
	print(f"%s %s%sFinished Cluster-Bomb attack on%s: {url}" % (good, underline, bold, end))
	print(Table)
	return Table
	
	
def output(table: str):
	"""Saves table to output path."""
	print(f"%s %s%sTable saved to file%s: {output_path}" % (good, underline, bold, end))
	with open(output_path, 'w') as output_p:
		output_p.write(table)

if __name__ == '__main__':
	table = main_menu()  # Gets the finalized table.
	output(table)        # Sends table to output func.
