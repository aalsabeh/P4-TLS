#!/usr/bin/python

import os
import sys
import binascii
from scapy.all import *

try:
    ip_dst = sys.argv[1]
except:
    ip_dst = "192.168.0.2"

try:
    iface = sys.argv[2]
except:
    iface="eth0"
    
if ip_dst == "10.0.0.2" or ip_dst == "192.168.0.2":
    mac_dst = "00:00:00:00:00:02"
elif ip_dst == "20.0.0.1":
    mac_dst = "00:00:00:00:00:03"
else:
    mac_dst = "ff:ff:ff:ff:ff:ff"    

 
def send_tls_client_hello(server_name):
    # Create TCP connection
    ip_layer = IP(dst="10.0.0.2")
    tcp_layer = TCP(dport=443)
    syn_packet = ip_layer / tcp_layer
 
    # Send SYN and receive SYN-ACK
    # syn_ack_packet = sr1(syn_packet)
 
    # Extract initial sequence number and acknowledgment number
    # initial_seq = syn_ack_packet[TCP].seq
    # ack_number = syn_ack_packet[TCP].ack
 
    
    # Create TLS Client Hello packet with SNI extension
    client_hello = (
        b'\x16' +                    # Content Type: Handshake (22)
        b'\x03\x01' +                # TLS Version: 1.0
        b'\x00\x00' +                # Length of the following handshake message (to be filled later)
        b'\x01' +                    # Handshake Type: Client Hello (1)
        b'\x00\x00\x00' +            # Length of the Client Hello message (to be filled later)
        b'\x03\x01' +                # TLS Version: 1.0
        os.urandom(32) +             # Random (32 bytes)
        b'\x01' +                    # Session ID Length: 1
        b'\x01' +
        b'\x00\x08' +                # Cipher Suites Length: 8
        b'\x00\x6b\x00\x6a\x00\x39\x00\x38' +  # Cipher Suites (TLS_RSA_WITH_AES_256_CBC_SHA, TLS_RSA_WITH_AES_128_CBC_SHA, TLS_RSA_WITH_RC4_128_SHA)
        b'\x01' +                    # Compression Methods Length: 1
        b'\x00' +                    # Compression Method: NULL
        b'\x00\x0e'                 # Extensions Length: 14
        # b'\x00\x00' +                # Type: server_name
        # b'\x00\x00' +                # Length
        # b'\x00\x00'                   # SNI Extension (Length: 0)
    )

    client_hello = (
        b'\x16' +                    # Content Type: Handshake (22)
        b'\x03\x03' +                # TLS Version: 1.2
        b'\x00\xd3' +                # Length of the following handshake message (to be filled later)
        b'\x01' +                    # Handshake Type: Client Hello (1)
        b'\x00\x00\xcf' +            # Length of the Client Hello message (to be filled later)
        b'\x03\x03' +                # TLS Version: 1.2
        os.urandom(32) +             # Random (32 bytes)
        b'\x00' +                    # Session ID Length: 0
        b'\x00\x26' +                # Cipher Suites Length: 38
        b'\x00\x6b\x00\x6a\x00\x39\x00\x38\x00\x6b\x00\x6a\x00\x39\x00\x38\x00\x38\x00\x6b\x00\x6a\x00\x39\x00\x38\x00\x38\x00\x6b\x00\x6a\x00\x39\x00\x38\x00\x38' +  # Cipher Suites 
        # b'\x00\x37' +                # Cipher Suites Length: 54
        # b'\x00\x6b\x00\x6a\x00\x39\x00\x38\x00\x6b\x00\x6a\x00\x39\x00\x38\x00\x38\x00\x6b\x00\x6a\x00\x39\x00\x38\x00\x38\x00\x6b\x00\x6a\x00\x39\x00\x38\x00\x38\x00\x38\x00\x6b\x00\x6a\x00\x39\x00\x38\x00\x38\x00\x39\x00\x38\x00' +  # Cipher Suites 
        # b'\xc0\x2c\xc0\x2b\xc0\x30\xc0\x2f\xc0\x24\xc0\x23\xc0\x28\xc0\x27\xc0\x0a\xc0\x09\xc0\x14\xc0\x13\x00\x9d\x00\x9c\x00\x3d\x00\x3c\x00\x35\x00\x2f\x00\x0a' # Cipher Suites
        b'\x01' +                    # Compression Methods Length: 1
        b'\x00' +                    # Compression Method: NULL
        b'\x00\x0e'                 # Extensions Length: 14
        # b'\x00\x00' +                # Type: server_name
        # b'\x00\x00' +                # Length
        # b'\x00\x00'                   # SNI Extension (Length: 0)
    )
 
    # Update lengths in the packet
    client_hello = client_hello[:3] + struct.pack('!H', len(client_hello) - 5) + client_hello[5:11] + struct.pack('!I', len(client_hello) - 11) + client_hello[15:]
 
    # Update the SNI extension with the desired server name
    sni_extension = (
        b'\x00\x00' +                # Extension Type: Server Name (0)

        struct.pack('!H', len(server_name.encode('utf-8')) + 5) +  # Extension Length: Length of the server name + 5

        struct.pack('!H', len(server_name.encode('utf-8')) + 3) +  # Server name list length

        b'\x00' +                # Server Name Indication (SNI) Type: Host Name (3)

        struct.pack('!H', len(server_name.encode('utf-8'))) +  # Length of the server name
        
        server_name.encode() +         # Server name
        (struct.pack("I", 0) * 10)
     )
 
    # Combine the TCP layer, TLS Client Hello, and SNI extension
    packet = (Ether(dst="10:70:fd:01:67:e1")/ 
            IP(dst=ip_dst, src="10.0.0.1") / 
            TCP(dport=443) / 
            (client_hello + sni_extension))

    sendp(packet, iface=iface)

 
# Replace "google.com" with the desired server name
send_tls_client_hello("facebook.com")

'''
import time
i = 0
for packet in PcapReader("malware_client_hellos.pcap"):
    i += 1
    if i <= 1:
        sendp(packet, iface="eth1")
        # print(packet.show())
    else:
        break
    time.sleep(0.1)
'''

pcap_file = "malware_client_hellos.pcap"
pcap_file = "dump_200.pcap"
fw = open("sent_packets_" + pcap_file + ".txt", 'w')
import time

def send_pcap(pcap_file):
	# '''
	i = 0
	ef = 0
	for packet in PcapReader(pcap_file):
		i += 1
		try:
			if TCP in packet and packet[TCP].dport == 443 and len(packet) > 64:
				
				packet = bytes(packet.original)
				# TLS header
				tcp_options_len = hex((packet[46] - 0x50))[:3]
				tcp_options_len_bytes = int(tcp_options_len,16) * 32 // 8
				tls_header = packet[54 + tcp_options_len_bytes:]
				tls_type = hex(tls_header[0])
				
				# TLS handshake type
				if tls_type != "0x16":
					continue
					
				# TLS handhskae - client hello
				tls_handshake_type = hex(tls_header[5])
				if tls_handshake_type != "0x1":
					continue 
							
				# if i == 4216:
				print(i)
				sendp(packet, iface=iface, verbose=0)
				time.sleep(0.01)
				
				# return
		except Exception as e:
			print(e)

# send_pcap(pcap_file)
    
# '''
def send_flowprint(directory):
	for subdirs, dirs, files in os.walk(directory):
		for file in files:
			if file.endswith('.pcap'):
				abs_path = os.path.join(subdirs, file)
				i = 0
				for packet in PcapReader(abs_path):
					i += 1
					try:
						if TCP in packet and packet[TCP].dport == 443 and len(packet) > 64:
							
							packet_bytes = bytes(packet.original)
							e = bytes(Ether(dst="10:70:fd:01:67:e1",type=0x0800))
							# Add ether
							new_packet = e + packet_bytes
							
							# TLS header
							tcp_options_len = hex((new_packet[46] - 0x50))[:3]
							tcp_options_len_bytes = int(tcp_options_len,16) * 32 // 8
							tls_header = new_packet[54 + tcp_options_len_bytes:]
							tls_type = hex(tls_header[0])
							
							# TLS handshake type
							if tls_type != "0x16":
								continue
								
							# TLS handhskae - client hello
							tls_handshake_type = hex(tls_header[5])
							if tls_handshake_type != "0x1":
								continue 
							
							# if i == 4216:
							print(abs_path, i)
							sendp(new_packet, iface=iface, verbose=0)
							time.sleep(0.01)
							
							# return
					except Exception as e:
						print(e)
				# break
							
					
					
				

# send_flowprint("flowprint/india/ios")
