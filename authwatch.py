#!/usr/bin/env python

#	Usage: python authWatch.py 
#	
# MODIFY THIS. Need to go grab scapy...need to make it spit data out into a report of some kind
#


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
	else:
		return True
def AddLineToDump(LineToAdd):
	if len(stores.args.dumpfile) > 1:
		lout = []
		lout.append(LineToAdd)
		f = open(stores.dumpfilename,'a')
		f.writelines(lout)
		f.close()

def sniffReq(p):
	# Look for a deauth packet and print the AP BSSID, Client BSSID and the reason for the deauth.
     if p.haslayer(Dot11Deauth):		
		line = p.sprintf("Deauth Found from AP [%Dot11.addr2%] Client [%Dot11.addr1%], Reason [%Dot11Deauth.reason%]")
		print line
		AddLineToDump(line)
	# Look for an association request packet and print the Station BSSID, Client BSSID, AP info.
     if p.haslayer(Dot11AssoReq):
     	line = p.sprintf("Association request from Station [%Dot11.addr1%], Client [%Dot11.addr2%], AP [%Dot11Elt.info%]")
		print line
		AddLineToDump(line)
	# Look for an authentication packet and print the Client and AP BSSID
	if p.haslayer(Dot11Auth):
		line = p.sprintf("Authentication Request from [%Dot11.addr1%] to AP [%Dot11.addr2%]")
		print p.sprintf("------------------------------------------------------------------------------------------")
		print line
		AddLineToDump(line)


def main(args):
	stores.args = args #stores the args in our proto class (line #27)	
	scpath = os.path.realpath(__file__)
	realdir = os.path.dirname(scpath)
	#check deps
	if not check_dependencies():
		print 'Dependency check failed. Please make sure you have all dependencies installed.'
		return
	if len(stores.args.dumpfile) > 1:
		stores.dumpfilename = stores.args.dumpfile + "/authwatch-gg-dumps-"+GetToday()
		cli.execute_shell("mkdir -p " + stores.args.dumpfile)
		lout = []
		f = open(stores.dumpfilename,'w')
		f.writelines(lout)
		f.close()

	sniff(iface=interface,prn=sniffReq)