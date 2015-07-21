#!/usr/bin/env python

import sys
import time
import cli
from scapy.all import *

class Proto:
	pass

const = Proto()
stores = Proto()

def GetToday():
	return str((time.strftime("%d-%m-%Y-%H:%M:%S")))

def check_dependencies():
	#CHECK FOR DEPENDENCIES
	if len(cli.check_sysfile('scapy'))==0:
		print 'scapy executable not found. Make sure you have installed scapy (pip install scapy) or this wont work.'
		return False
	if len(cli.check_sysfile('airmon-ng'))==0:
		print 'airmon-ng executable not found. Make sure you have installed scapy (pip install scapy) or this wont work.'
		return False
	else:
		return True

def ValidInterface():
	avail = False
	wlan = stores.args.interface
	if stores.args.verbose: print 'Looking for: ' + wlan
	if not "mon" in wlan:
		print 'You must select a monitor interface (ie. mon0, mon1, etc).'
		return
	if stores.args.verbose: print 'Verifying wireless interface is available...'
	s=cli.execute_shell('ifconfig | grep ' + wlan)
	lines = s.splitlines()
	if stores.args.verbose: print lines

	for line in lines:
		if wlan in line:
			avail = True

	if avail:
		if stores.args.verbose: print 'Interface found.'
		return True
	else:
		if stores.args.verbose: print 'Looking a little deeper for that interface you asked for.'
		s2=cli.execute_shell('ifconfig -a | grep ' + wlan)
		lines = s.splitlines()
		if stores.args.verbose: print lines
		for line in lines:
			if wlan in line:
				if stores.args.verbose: print 'Interface was found...but its not up. You need to fix that.'

		if stores.args.verbose: print 'Interface NOT found anywhere.'
		return False

#Add lines to the dump file
def AddLineToDump(LineToAdd):
	if len(stores.args.dumpfile) > 1: #check to make sure the dump file exists
		lout = []
		lout.append(LineToAdd+'\n')
		f = open(stores.dumpfilename,'a')
		f.writelines(lout)
		f.close()

def sniffReq(p):

	if p.haslayer(Dot11Deauth) and not stores.args.deauthignore:
		# Look for a deauth packet and print the AP BSSID, Client BSSID and the reason for the deauth.
		line = p.sprintf("Deauth Found from AP [%Dot11.addr2%] Client [%Dot11.addr1%], Reason [%Dot11Deauth.reason%]")
		print line
		AddLineToDump(line)
	if p.haslayer(Dot11AssoReq) and not stores.args.assocignore:
		# Look for an association request packet and print the Station BSSID, Client BSSID, AP info.
		line = p.sprintf("Association request from Station [%Dot11.addr1%], Client [%Dot11.addr2%], AP [%Dot11Elt.info%]")
		print line
		AddLineToDump(line)

	if p.haslayer(Dot11Auth) and not stores.args.authignore:
		# Look for an authentication packet and print the Client and AP BSSID
		line = p.sprintf("Authentication Request from [%Dot11.addr1%] to AP [%Dot11.addr2%]")
		print p.sprintf("------------------------------------------------------------------------------------------")
		print line
		AddLineToDump(line)

def start_sniff():
	sniff(iface=stores.args.interface,prn=sniffReq)

def main(args):
	stores.args = args #stores the args in our structure so any function can retrieve them
	scpath = os.path.realpath(__file__)
	realdir = os.path.dirname(scpath)
	cli.arguments = args #initialize args for cli
	#announce verbose
	if args.verbose: print 'Verbose argument given...prepare to get info...'

	#check deps
	if not check_dependencies():
		print 'Dependency check failed. Please make sure you have all dependencies installed.'
		return

	#check to make sure that the selected interface is valid
	if not ValidInterface():
		print 'The interface you selected is not valid or does not exist.'
		return

	if not stores.args.dumpfile == "": #If a name is specified for the dump file then create it
		if stores.args.verbose: print "Dump file argument given. Creating dump file."
		stores.dumpfilename = stores.args.dumpfile + "/authwatch-gg-dump"
		if not os.path.exists(stores.args.dumpfile):
			if stores.args.verbose: print "Path does not exist trying to create it."
			cli.execute_shell("mkdir -p " + stores.args.dumpfile)
		lout = []
		f = open(stores.dumpfilename,'w')
		f.writelines(lout)
		f.close()
		if stores.args.verbose: print "Dump file with the name " + stores.dumpfilename + " successfully created."

	print "authwatch running..."
	start_sniff()
