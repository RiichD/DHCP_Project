#!/bin/python3

import socket as s
import time as t
import struct as st
import random as r
import threading as th
import json
#<!> DO NOT CHANGE VALUE BELOW <!>
serverIP = ""
serverPort = 67

server = s.socket(s.AF_INET, s.SOCK_DGRAM)
server.setsockopt(s.SOL_SOCKET, s.SO_REUSEPORT, 1)
server.setsockopt(s.SOL_SOCKET, s.SO_BROADCAST, 1) # Broadcast
server.bind((serverIP, serverPort))
print("server (" +  serverIP + "," + str(serverPort) + ") ready")

DHCP_IP = ""
DHCP_MASK_IP = ""
CLIENT_FIRST_ADDR = ""
CLIENT_last_ADDR = ""
TARGET_IP = "" # Broadcast IP
ROUTER_IP = ""
LEASE_TIME_IP = ""
DNS_IP1 = ""
DNS_IP2 = ""
DNS_NAME = ""

log_lock = th.Lock() # Lock for log_update()
log_database = th.Lock() # Lock for log_database_update()

ip_state_list = {} # List that contains every IP

# Value below can be changed
config_file_name = "conf.txt"

"""
DHCP Format length in byte.
"""
dhcp_format = [
	{'field':'op_code', 'name':'operation_code', 'length':1, 'type':int},
	{'field':'htype', 'name':'hardware_type', 'length':1, 'type':int},
	{'field':'hlen', 'name':'hardware_address_length', 'length':1, 'type':int},
	{'field':'hops', 'name':'hops', 'length':1, 'type':int},
	{'field':'xid', 'name':'transaction_identifier', 'length':4, 'type':hex},
	{'field':'secs', 'name':'seconds', 'length':2, 'type':int},
	{'field':'flags', 'name':'flags', 'length':2, 'type':hex},
	{'field':'ciaddr', 'name':'client_ip_address', 'length':4, 'type':hex}, #IP
	{'field':'yiaddr', 'name':'your_ip_address', 'length':4, 'type':hex}, #IP
	{'field':'siaddr', 'name':'server_ip_address', 'length':4, 'type':hex}, #IP
	{'field':'giaddr', 'name':'gateway_ip_address', 'length':4, 'type':hex}, #IP
	{'field':'chaddr', 'name':'client_hardware_address', 'length':16, 'type':hex}, #MAC
	{'field':'sname', 'name':'server_name', 'length':64, 'type':str},
	{'field':'file', 'name':'boot_file_name', 'length':128, 'type':str},
	{'field':'options', 'name':'options', 'length':0, 'type':hex} # length 0 == variable
]

dhcp_options = {
	'option_0':{'id':0, 'name':'padding', 'type': hex},
	'option_1':{'id':1, 'name':'subnet_mask', 'type': hex}, #IP
	'option_3':{'id':3, 'name':'router_ip', 'type': hex}, #IP
	'option_6':{'id':6, 'name':'domain_name_server', 'type': hex}, #IP
	'option_12':{'id':12, 'name':'hostname', 'type': str},
	'option_15':{'id':15, 'name':'domain_name', 'type': str},
	'option_28':{'id':28, 'name':'broadcast_address', 'type': hex}, #IP
	'option_50':{'id':50, 'name':'requested_ip_address', 'type': hex}, #IP
	'option_51':{'id':51, 'name':'ip_address_lease_time', 'type': int},
	'option_53':{'id':53, 'name':'dhcp_message_type', 'type': int},
	'option_54':{'id':54, 'name':'dhcp_server_identifier', 'type': hex}, #IP
	'option_57':{'id':57, 'name':'maximum_dhcp_message_size', 'type': int},
	'option_58':{'id':58, 'name':'renewal_time_value', 'type': int},
	'option_59':{'id':59, 'name':'rebinding_time_value', 'type': int},
	'option_61':{'id':61, 'name':'client_id', 'type': hex}, #MAC
	'option_255':{'id':255, 'name':'end', 'type': int}
}

"""
DHCP Server configuration
"""
def config_server():
	print("Configuring server")
	config_file = open(config_file_name, 'r')
	file_content = config_file.readlines()
	server_params = {}
	for item in file_content:
		x,y = item.split(':')
		server_params[x] = y[:-1] # Remove newline
	config_file.close()
	return server_params

"""
Data reader
"""
def data_decoder(data):
	"""
	Function to decode data depending on dhcp_format.
	"""
	b_pos = 0 # Byte position
	decoded_data = []
	for dhcp_f in dhcp_format:
		value = {}
		if dhcp_f['field'] == "options":
			value[dhcp_f['field']] = data[b_pos:]
			decoded_data.append(value)
			break
		value[dhcp_f['field']] = data[b_pos:b_pos+dhcp_f['length']]
		decoded_data.append(value)
		b_pos+=dhcp_f['length']
	return decoded_data

def options_decoder(data):
	opt_data = data[14]['options']

	b_pos = 4 # Starts at 4 to ignore magic cookie
	opt_size = len(opt_data)

	decoded_option = {}
	while b_pos < opt_size:
		if opt_data[b_pos] == 255:
			break
		opt = opt_data[b_pos]
		b_pos += 1
		opt_len = opt_data[b_pos]
		b_pos += 1
		result = ''
		i = b_pos
		while b_pos < i + opt_len:
			result += str(opt_data[b_pos])
			if b_pos + 1 < i + opt_len:
				result += " "
			b_pos += 1
		decoded_option['option_'+str(opt)] = {'id':opt, 'length':opt_len, 'data':result}
	return decoded_option

def options_translator(opt):
	if opt['id'] == 50:
		return opt['data'].replace(' ', '.')

def string_to_byte(string):
	byte=b''
	for b in string:
		byte=byte+bytes([ord(b)])
	return byte

def check_message_type(data):
	"""
	Function to check message type (DISCOVER, OFFER, REQUEST, ACK).
	Return :
	1 for DISCOVER
	2 for OFFER
	3 for REQUEST
	5 for ACK
	"""
	options = data[14]['options']
	if options[6:7].hex() == '01':
		return 1
	elif options[6:7].hex() == '02':
		return 2
	elif options[6:7].hex() == '03':
		return 3
	elif options[6:7].hex() == '05':
		return 5

"""
DHCP Services
"""
def dhcp_offer(data, addr, ip):
	print(ip)
	value = {}
	value[dhcp_format[0]['field']] = b'\x02' # op_code
	value[dhcp_format[1]['field']] = b'\x01' # htype
	value[dhcp_format[2]['field']] = b'\x06' # hlen
	value[dhcp_format[3]['field']] = b'\x00' # hops
	value[dhcp_format[4]['field']] = data[4]['xid'] # xid
	value[dhcp_format[5]['field']] = b'\x00\x00' # secs
	value[dhcp_format[6]['field']] = b'\x00\x00' # flags
	value[dhcp_format[7]['field']] = data[7]['ciaddr'] # ciaddr
	value[dhcp_format[8]['field']] = s.inet_aton(ip) # yiaddr
	value[dhcp_format[9]['field']] = s.inet_aton(DHCP_IP) # siaddr
	value[dhcp_format[10]['field']] = data[10]['giaddr'] # giaddr
	value[dhcp_format[11]['field']] = data[11]['chaddr'] # chaddr
	value[dhcp_format[12]['field']] = bytearray(64) # sname
	value[dhcp_format[13]['field']] = bytearray(128) # file

	magic_cookie = s.inet_aton('99.130.83.99') # Default value
	DHCPOptions1 = bytes([53, 1, 2]) # => option 53, length 1, DHCP Offer
	DHCPOptions2 = bytes([1, 4]) + s.inet_aton(DHCP_MASK_IP) # Subnet mask
	DHCPOptions3 = bytes([3, 4]) + s.inet_aton(ROUTER_IP) # Router
	DHCPOptions4 = bytes([51, 4]) + s.inet_aton(str(LEASE_TIME_IP)) # IP lease time
	DHCPOptions5 = bytes([54, 4]) + s.inet_aton(DHCP_IP) # DHCP server
	DHCPOptions6 = bytes([28, 4]) + s.inet_aton(TARGET_IP) # Broadcast IP
	if DNS_IP2 != "":
		DHCPOptions7 = bytes([6, 8]) + s.inet_aton(DNS_IP1) + s.inet_aton(DNS_IP2) # DNS IP
	elif DNS_IP1 != "":
		DHCPOptions7 = bytes([6, 4]) + s.inet_aton(DNS_IP1)
	if DNS_NAME != "":
		DHCPOptions8 = bytes([15, len(DNS_NAME)]) + string_to_byte(DNS_NAME) # DNS NAME
	data_to_send = b""

	for val in value.values():
		data_to_send += val

	data_to_send += magic_cookie
	data_to_send += DHCPOptions1
	data_to_send += DHCPOptions2
	data_to_send += DHCPOptions3
	data_to_send += DHCPOptions4
	data_to_send += DHCPOptions5
	data_to_send += DHCPOptions6
	if DNS_IP1 != "" or DNS_IP2 != "":
		data_to_send += DHCPOptions7 
	if DNS_NAME != "":
		data_to_send += DHCPOptions8
	data_to_send += bytes([255])

	print(f"Data to send:\n{data_to_send}\n")
	server.sendto(data_to_send, (TARGET_IP, 68))
	server.sendto(data_to_send, addr)
	print(f"DHCP Offer data sent to:{addr}\n")
	return data_to_send

def dhcp_ack(data, addr, ip):
	value = {}
	value[dhcp_format[0]['field']] = b'\x02' # op_code
	value[dhcp_format[1]['field']] = b'\x01' # htype
	value[dhcp_format[2]['field']] = b'\x06' # hlen
	value[dhcp_format[3]['field']] = b'\x00' # hops
	value[dhcp_format[4]['field']] = data[4]['xid'] # xid
	value[dhcp_format[5]['field']] = b'\x00\x00' # secs
	value[dhcp_format[6]['field']] = b'\x00\x00' # flags
	value[dhcp_format[7]['field']] = data[7]['ciaddr'] # ciaddr
	
	if data[7]['ciaddr'] == s.inet_aton('0.0.0.0'):
		print("Should be option 50 in the packet")
		requested_ip = options_translator(options_decoder(data)['option_50'])
		print(f"Client requested: {requested_ip}\n")

		if not ip_state_list[requested_ip]['busy'] or ip_state_list[requested_ip]['client_mac'] == str(data[11]['chaddr']):

			print(f"{requested_ip} accepted!\n")
			value[dhcp_format[8]['field']] = s.inet_aton(requested_ip) # yiaddr
		else:
			print(f"{requested_ip} refused! Server gives {ip}\n")
			print("fnzifbzueifb",ip)
			value[dhcp_format[8]['field']] = s.inet_aton(ip) # yiaddr
	else:
		print("No option 50, an ip is chosen by the dhcp server")
		value[dhcp_format[8]['field']] = data[7]['ciaddr'] # yiaddr
	
	value[dhcp_format[9]['field']] = s.inet_aton(DHCP_IP) # siaddr
	value[dhcp_format[10]['field']] = data[10]['giaddr'] # giaddr
	value[dhcp_format[11]['field']] = data[11]['chaddr'] # chaddr
	value[dhcp_format[12]['field']] = bytearray(64) # sname
	value[dhcp_format[13]['field']] = bytearray(128) # file

	magic_cookie = s.inet_aton('99.130.83.99') # Default value
	DHCPOptions1 = bytes([53, 1, 5]) # => option 53, length 1, DHCP Ack
	DHCPOptions2 = bytes([1, 4]) + s.inet_aton(DHCP_MASK_IP) # Subnet mask
	DHCPOptions3 = bytes([3, 4]) + s.inet_aton(ROUTER_IP) # Router
	DHCPOptions4 = bytes([51, 4]) + s.inet_aton(str(LEASE_TIME_IP)) # IP lease time
	DHCPOptions5 = bytes([54, 4]) + s.inet_aton(DHCP_IP) # DHCP server
	DHCPOptions6 = bytes([28, 4]) + s.inet_aton(TARGET_IP) # Broadcast IP
	if DNS_IP2 != "":
		DHCPOptions7 = bytes([6, 8]) + s.inet_aton(DNS_IP1) + s.inet_aton(DNS_IP2) # DNS IP
	elif DNS_IP1 != "":
		DHCPOptions7 = bytes([6, 4]) + s.inet_aton(DNS_IP1)
	if DNS_NAME != None:
		DHCPOptions8 = bytes([15, len(DNS_NAME)]) + string_to_byte(DNS_NAME) # DNS NAME
	data_to_send = b""

	for val in value.values():
		data_to_send += val

	data_to_send += magic_cookie
	data_to_send += DHCPOptions1
	data_to_send += DHCPOptions2
	data_to_send += DHCPOptions3
	data_to_send += DHCPOptions4
	data_to_send += DHCPOptions5
	data_to_send += DHCPOptions6
	if DNS_IP1 != "" or DNS_IP2 != "":
		data_to_send += DHCPOptions7
	if DNS_NAME != "":
		data_to_send += DHCPOptions8
	data_to_send += bytes([255])

	print(f"Data to send:\n{data_to_send}\n")
	ip = s.inet_ntoa(value[dhcp_format[8]['field']])
	print("the ip in the packet : ", ip)
	ip_state_list[ip]['busy'] = True
	ip_state_list[ip]['client_mac'] = str(data[11]['chaddr'])
	ip_state_list[ip]['lease_time'] = t.time()
	server.sendto(data_to_send, (TARGET_IP, 68))
	#server.sendto(data_to_send, addr)
	print(f"DHCP Ack data sent to:{addr}\n")
	return data_to_send

def ip_selection(ip_state_list, randomize):
	"""
	Function that select an ip address that is available
	"""
	if randomize:
		# Checks if an IP is available
		available = False
		for ip_addr in ip_state_list:
			if not ip_state_list[ip_addr]['busy']:
				available = True
				break
		if not available:
			return ''
		
		# Random IP
		ip_address = random_ip_generator(CLIENT_FIRST_ADDR, CLIENT_LAST_ADDR)
		while ip_state_list[ip_address]['busy']:
			ip_address = random_ip_generator(CLIENT_FIRST_ADDR, CLIENT_LAST_ADDR)
		print(f"Random IP between {CLIENT_FIRST_ADDR} and {CLIENT_LAST_ADDR}: {ip_address}\n")
		return ip_address
	else:
		for ip_address in ip_state_list:
			if not ip_state_list[ip_address]['busy']:
				return ip_address
	return ''

def random_ip_generator(first, last):
	"""
	Function that generates ip between the first and the last.
	"""
	interval = r.randint(int(s.inet_aton(first).hex(), 16), int(s.inet_aton(last).hex(), 16))
	ip = s.inet_ntoa(s.inet_aton(hex(interval)))
	return ip

def ips(start, end):
	"""
	Function that generates ip between start and end
	"""
	start = st.unpack('>I', s.inet_aton(start))[0]
	end = st.unpack('>I', s.inet_aton(end))[0] + 1
	return [s.inet_ntoa(st.pack('>I', i)) for i in range(start, end)]

"""
DHCP Updates
"""
def log_update(data):
	log_lock.acquire()
	f = open("log_file.txt", "a+")
	f.write(data)
	f.close()
	log_lock.release()

def log_database_update():
	log_database.acquire()
	f = open("database.txt", "w")
	for state in ip_state_list:
		f.write(str(state)+ ': ' + str(ip_state_list[state]) + '\n')
	f.close()
	log_database.release()

"""
Else
"""
def handle_client(data, addr, client_ip):
	print(f"Server received:\n{data}\n")
	decoded_data = data_decoder(data)
	msg_type = check_message_type(decoded_data)
	options_decoder(decoded_data)
	if msg_type == 1:
		print("DISCOVER message\n")
		resp_data = dhcp_offer(decoded_data, addr, client_ip) # DHCP OFFER
		log_update(f"DISCOVER:\n{str(data)}\n")
		log_update(f"OFFER:\n{str(resp_data)}\n")
	elif msg_type == 3:
		print("REQUEST message\n")
		resp_data = dhcp_ack(decoded_data, addr, client_ip) # DHCP ACK
		log_database_update()
		log_update(f"REQUEST:\n{str(data)}\n")
		log_update(f"ACK:\n{str(resp_data)}\n")

def clear_ip_state_list():
	for ip in ip_state_list:
	
		if (int(ip_state_list[ip]['lease_time']) - int(LEASE_TIME_IP) <= 0):
			ip_state_list[ip]['busy'] = False
			
def start():
	while True:
		data, addr = server.recvfrom(2048) # DHCP DISCOVER OR REQUEST
		selected_ip = ""
		
		selected_ip = ip_selection(ip_state_list, True)
		if selected_ip == "":
			clear_ip_state_list()
			selected_ip = ip_selection(ip_state_list, True)
			print("Selected ip: ", selected_ip)
			if selected_ip == "":
				print("No ip available in the DHCP Server")
		
		if selected_ip != '0.0.0.0' and selected_ip != '':			
			print("Selected ip: ", selected_ip)
			th.Thread(target=handle_client(data, addr, selected_ip))
"""
MAIN
"""
# Configurating DHCP server
config = config_server()
DHCP_IP = config['network_addr']
DHCP_MASK_IP = config['network_mask']
CLIENT_FIRST_ADDR = config['client_first_addr']
CLIENT_LAST_ADDR = config['client_last_addr']
ROUTER_IP = config['router_ip']
TARGET_IP = config['broadcast_ip']
LEASE_TIME_IP = config['client_lease_time']
DNS_IP1 = config['dns_addr1']
DNS_IP2 = config['dns_addr2']
DNS_NAME = config['dns_name']

# Check information
print(f'Server Configuration:\n')
print(f'Server dhcp IP:{DHCP_IP}')
print(f'Server subnet mask IP:{DHCP_MASK_IP}')
print(f'Server client first IP:{CLIENT_FIRST_ADDR}')
print(f'Server client last IP:{CLIENT_LAST_ADDR}')
print(f'Server router IP:{ROUTER_IP}')
print(f'Server target(broadcast) IP:{TARGET_IP}')
print(f'Server domain name:{TARGET_IP}')
print(f'Server lease time IP:{LEASE_TIME_IP}\n')

if DHCP_IP == '' or DHCP_MASK_IP == '' or CLIENT_FIRST_ADDR == '' or CLIENT_LAST_ADDR == '' or ROUTER_IP == '' or TARGET_IP == '' or LEASE_TIME_IP == '':
	print(f"Your file {config_file_name} is not well structured, please modify it.\n")

# IP initialization
adresses = ips(CLIENT_FIRST_ADDR, CLIENT_LAST_ADDR)
for address in adresses:
	ip_state_list[address] = {'busy':False, "client_mac":'', 'lease_time':0}

# Starts DHCP server
start()
