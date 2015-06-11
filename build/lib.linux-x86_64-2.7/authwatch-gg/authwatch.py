#!/usr/bin/env python

import sys
import time
from scapy.all import *

class Proto:
	pass
	
const = Proto()
stores = Proto() #struct to dump misc crap in...like args (see main)

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
	avail = ""
	wlan = stores.args.interface
	if not "mon" in wlan: print 'You must select a monitor interface (ie. mon0, mon1, etc).'
	if stores.args.verbose: print 'Verifying wireless interface is available...'
	s=cli.execute_shell('ifconfig')
	lines = s.splitlines()
	bwlan = False
	
	for line in lines:
		if not line.startswith(' ') and len(line)>0:
			text=line.split(' ')[0]
			if text.startswith(wlan):
				#avail = avail + text
				bwlan = True
				
	if not bwlan:
		print wlan + ' interface was not found. Make sure the interface you selected is up.'
		return False
	else:
		if stores.args.verbose: print 'Interface found.'
		#if stores.args.verbose: print 'Available interfaces: ' + avail
		return True

def AddLineToDump(LineToAdd):
	if len(stores.args.dumpfile) > 1:
		lout = []
		lout.append(LineToAdd)
		f = open(stores.dumpfilename,'a')
		f.writelines(lout)
		f.close()

def sniffReq(p):
	
	if p.haslayer(Dot11Deauth):	
		# Look for a deauth packet and print the AP BSSID, Client BSSID and the reason for the deauth.	
		line = p.sprintf("Deauth Found from AP [%Dot11.addr2%] Client [%Dot11.addr1%], Reason [%Dot11Deauth.reason%]")
		print line
		AddLineToDump(line)
	if p.haslayer(Dot11AssoReq):
		# Look for an association request packet and print the Station BSSID, Client BSSID, AP info.
		line = p.sprintf("Association request from Station [%Dot11.addr1%], Client [%Dot11.addr2%], AP [%Dot11Elt.info%]")
		print line
		AddLineToDump(line)
	
	if p.haslayer(Dot11Auth):
		# Look for an authentication packet and print the Client and AP BSSID
		line = p.sprintf("Authentication Request from [%Dot11.addr1%] to AP [%Dot11.addr2%]")
		print p.sprintf("------------------------------------------------------------------------------------------")
		print line
		AddLineToDump(line)


def main(args):
	stores.args = args 
	scpath = os.path.realpath(__file__)
	realdir = os.path.dirname(scpath)
	#check deps
	if not check_dependencies():
		print 'Dependency check failed. Please make sure you have all dependencies installed.'
		return

	if not ValidInterface():
		print 'The interface you selected is not valid or does not exist.'
		return

	if len(stores.args.dumpfile) > 1:
		if stores.args.verbose: print "Dump file argument given. Creating dump file."
		stores.dumpfilename = stores.args.dumpfile + "/authwatch-gg-dumps-"+GetToday()
		cli.execute_shell("mkdir -p " + stores.args.dumpfile)
		lout = []
		f = open(stores.dumpfilename,'w')
		f.writelines(lout)
		f.close()
		if stores.args.verbose: print "Dump file with the name " + stores.dumpfile + " successfully created."
	sniff(iface=interface,prn=sniffReq)