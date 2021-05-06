#!/bin/python3

import socket as s
import time as t
import struct
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
target_ip = "" # Broadcast IP
ROUTER_IP = ""
LEASE_TIME_IP = -1

log_lock = th.Lock() # Lock for log_update()

ip_state_list = {}
'''examples
ip_state_list = {
	'192.168.102.201':{'busy':False, 'client_mac':'00000000', 'lease_time':0},
	'192.168.102.202':{'busy':True, 'client_mac':'0099887766', 'lease_time':768},
	'192.168.102.203':{'busy':False, 'client_mac':'00000000', 'lease_time':0},
	'192.168.102.204':{'busy':True, 'client_mac':'0011223344', 'lease_time':20}
}'''



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

def config_server():
	print("Configuring server")
	config_file = open("conf.txt", 'r')
	file_content = config_file.readlines()
	server_params = {}
	for item in file_content:
		x,y = item.split(':')
		server_params[x] = y[:-1] # Remove newline
	config_file.close()
	return server_params

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

def dhcp_offer(data, addr, ip):
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

	data_to_send = b""

	for val in value.values():
		data_to_send += val

	data_to_send += magic_cookie
	data_to_send += DHCPOptions1
	data_to_send += DHCPOptions2
	data_to_send += DHCPOptions3
	data_to_send += DHCPOptions4
	data_to_send += DHCPOptions5
	data_to_send += bytes([255])

	print(f"Data to send:\n{data_to_send}\n")
	server.sendto(data_to_send, (target_ip, 68))
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
	value[dhcp_format[8]['field']] = s.inet_aton(ip) # yiaddr
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
	data_to_send = b""

	for val in value.values():
		data_to_send += val

	data_to_send += magic_cookie
	data_to_send += DHCPOptions1
	data_to_send += DHCPOptions2
	data_to_send += DHCPOptions3
	data_to_send += DHCPOptions4
	data_to_send += DHCPOptions5
	data_to_send += bytes([255])

	print(f"Data to send:\n{data_to_send}\n")
	ip_state_list[ip]['busy'] = True
	ip_state_list['mac_adress'] = str(data[11]['chaddr'])
	ip_state_list['lease_time'] = t.time()
	server.sendto(data_to_send, (target_ip, 68))
	server.sendto(data_to_send, addr)
	print(f"DHCP Ack data sent to:{addr}\n")


	return data_to_send

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

def options_reader(data):
	opt_data = data[14]['options']

	b_pos = 4 # Starts at 4 to ignore magic cookie
	opt_size = len(opt_data)

	while b_pos < opt_size:
		if opt_data[b_pos] == 255:
			break
		print(f"Option {opt_data[b_pos]}, ")
		b_pos += 1
		print(f"Length {opt_data[b_pos]}, ")
		opt_len = opt_data[b_pos] + b_pos + 1
		b_pos += 1
		result = ''
		while b_pos < opt_len and b_pos < opt_size:
			result += str(opt_data[b_pos]) + " "
			b_pos += 1
		print(result)

def ip_selection(ip_state_list):
	"""
	Function that select an ip address that is available
	"""
	for ip_adress in ip_state_list:
		if not ip_state_list[ip_adress]['busy']:
			return ip_adress
	return ''

def random_ip_generator(first, last):
	"""
	Function that generates ip between the lowest and the highest.
	"""
	interval = r.randint(int(s.inet_aton(first).hex(), 16), int(s.inet_aton(last).hex(), 16))
	ip = s.inet_ntoa(s.inet_aton(hex(interval)))
	print(f"Random IP between {first} and {last}: {ip}\n")
	return ip


def log_update(data):
	log_lock.acquire()
	f = open("log_file", "a+")
	f.write(data)
	f.close()
	log_lock.release()

def log_database_update():
	f = open("database.txt", "w")
	f.write(json.dumps(ip_state_list))
	f.close()


def handle_client(data, addr, client_ip):
	print(f"Server received:\n{data}\n")
	decoded_data = data_decoder(data)
	msg_type = check_message_type(decoded_data)
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




# Configurating DHCP server
config = config_server()
DHCP_IP = config['network_addr']
DHCP_MASK_IP = config['network_mask']
CLIENT_FIRST_ADDR = config['client_first_addr']
CLIENT_LAST_ADDR = config['client_last_addr']
ROUTER_IP = config['router_ip']
target_ip = config['broadcast_ip']
LEASE_TIME_IP = config['client_lease_time']

# Check information
print(f'Server Configuration:\n')
print(f'Server dhcp IP:{DHCP_IP}')
print(f'Server subnet mask IP:{DHCP_MASK_IP}')
print(f'Server client first IP:{CLIENT_FIRST_ADDR}')
print(f'Server client last IP:{CLIENT_LAST_ADDR}')
print(f'Server router IP:{ROUTER_IP}')
print(f'Server target(broadcast) IP:{target_ip}')
print(f'Server lease time IP:{LEASE_TIME_IP}\n')

def start():
	while True:
		data, addr = server.recvfrom(2048) # DHCP DISCOVER OR REQUEST
		selected_ip = ip_selection(ip_state_list)
		generated_ip = random_ip_generator(CLIENT_FIRST_ADDR, CLIENT_LAST_ADDR)
		th.Thread(target=handle_client(data, addr, generated_ip))

def ips(start, end):
    import socket, struct
    start = struct.unpack('>I', socket.inet_aton(start))[0]
    end = struct.unpack('>I', socket.inet_aton(end))[0]
    return [socket.inet_ntoa(struct.pack('>I', i)) for i in range(start, end)]


# Initialization of the ip

adresses = ips(CLIENT_FIRST_ADDR, CLIENT_LAST_ADDR)

for adress in adresses:
	ip_state_list[adress] = {'busy':False, "client_mac":'', 'lease_time':''}

# Starts DHCP server
start()
