import socket as s
import time as t
import struct
from threading import *
import random as r

#<!> DO NOT CHANGE VALUE BELOW <!>
serverIP = ""
serverPort = 67

server = s.socket(s.AF_INET, s.SOCK_DGRAM)
server.setsockopt(s.SOL_SOCKET, s.SO_REUSEPORT, 1)
server.setsockopt(s.SOL_SOCKET, s.SO_BROADCAST, 1) # Broadcast
server.bind((serverIP, serverPort))
print("server (" +  serverIP + "," + str(serverPort) + ") ready")

# Value below can be changed
dhcp_ip = "192.168.102.5"
subnet_mask_ip = "255.255.255.0"

client_ip = "192.168.102.50"
client_first_addr = "192.168.102.100"
client_last_addr = "192.168.102.200"
target_ip = "192.168.102.0" # Broadcast IP

# Optional value
router_ip = "192.168.102.5"
lease_time_ip = 86400

print(f'Server Configuration:\n')
print(f'Server dhcp IP:{dhcp_ip}')
print(f'Server subnet mask IP:{subnet_mask_ip}')
print(f'Server client IP:{client_ip}')
print(f'Server target(broadcast) IP:{target_ip}\n')

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
	{'field':'ciaddr', 'name':'client_ip_address', 'length':4, 'type':hex},
	{'field':'yiaddr', 'name':'your_ip_address', 'length':4, 'type':hex},
	{'field':'siaddr', 'name':'server_ip_address', 'length':4, 'type':hex},
	{'field':'giaddr', 'name':'gateway_ip_address', 'length':4, 'type':hex},
	{'field':'chaddr', 'name':'client_hardware_address', 'length':16, 'type':hex},
	{'field':'sname', 'name':'server_name', 'length':64, 'type':int},
	{'field':'file', 'name':'boot_file_name', 'length':128, 'type':int},
	{'field':'options', 'name':'options', 'length':0, 'type':int}
]

def data_decoder(data):
	"""
	Function to decode data depending on dhcp_format.
	"""
	print("Decoding data...")

	b_pos = 0 #Byte position

	decoded_data = []

	for dhcp_f in dhcp_format:
		value = {}
		if dhcp_f['field'] == "options": #Ignore options
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
	value[dhcp_format[9]['field']] = s.inet_aton(dhcp_ip) # siaddr
	value[dhcp_format[10]['field']] = data[10]['giaddr'] # giaddr
	value[dhcp_format[11]['field']] = data[11]['chaddr'] # chaddr
	value[dhcp_format[12]['field']] = bytearray(64) # sname
	value[dhcp_format[13]['field']] = bytearray(128) # file

	magic_cookie = s.inet_aton('99.130.83.99') # Default value
	DHCPOptions1 = bytes([53, 1, 2]) # => option 53, length 1, DHCP Offer
	DHCPOptions2 = bytes([1, 4]) + s.inet_aton(subnet_mask_ip) # Subnet mask
	DHCPOptions3 = bytes([3, 4]) + s.inet_aton(router_ip) # Router
	DHCPOptions4 = bytes([51, 4]) + s.inet_aton(str(lease_time_ip)) # IP lease time
	DHCPOptions5 = bytes([54, 4]) + s.inet_aton(dhcp_ip) # DHCP server

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
	value[dhcp_format[9]['field']] = s.inet_aton(dhcp_ip) # siaddr
	value[dhcp_format[10]['field']] = data[10]['giaddr'] # giaddr
	value[dhcp_format[11]['field']] = data[11]['chaddr'] # chaddr
	value[dhcp_format[12]['field']] = bytearray(64) # sname
	value[dhcp_format[13]['field']] = bytearray(128) # file

	magic_cookie = s.inet_aton('99.130.83.99') # Default value
	DHCPOptions1 = bytes([53, 1, 5]) # => option 53, length 1, DHCP Ack
	DHCPOptions2 = bytes([1, 4]) + s.inet_aton(subnet_mask_ip) # Subnet mask
	DHCPOptions3 = bytes([3, 4]) + s.inet_aton(router_ip) # Router
	DHCPOptions4 = bytes([51, 4]) + s.inet_aton(str(lease_time_ip)) # IP lease time
	DHCPOptions5 = bytes([54, 4]) + s.inet_aton(dhcp_ip) # DHCP server
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

	print("options")
	if options[6:7].hex() == '01':
		print("DISCOVER\n")
		return 1
	elif options[6:7].hex() == '02':
		print("OFFER\n")
		return 2
	elif options[6:7].hex() == '03':
		print("REQUEST\n")
		return 3
	elif options[6:7].hex() == '05':
		print("ACK\n")
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

def random_ip_generator(first, last):
	"""
	Function that generates ip between the lowest and the highest.
	"""
	interval = r.randint(int(s.inet_aton(first).hex(), 16), int(s.inet_aton(last).hex(), 16))
	ip = s.inet_ntoa(s.inet_aton(hex(interval)))
	print(f"Random IP between {first} and {last}: {ip}\n")
	return ip

def check_ip_avaibility(ip):
	"""
	Function to check if ip is available.
	"""

def config_serveur():
	print("configuring the serveur")
	config_file = open("conf.txt", 'r')
	file_content = config_file.readlines()
	print(file_content)
	serveur_params = {}
	for item in file_content:
		x,y = item.split(':')
		serveur_params[x] = y[:-1]
	print(serveur_params)
	config_file.close()

def handle_client():
	while True:
		data, addr = server.recvfrom(2048) # DHCP DISCOVER OR REQUEST
		print(f"Server has received:\n{data}\n")

		decoded_data = data_decoder(data)
		#print(f"{decoded_data}\n")

		#options_reader(decoded_data)
		msg_type = check_message_type(decoded_data)
		if msg_type == 1:
			resp_data = dhcp_offer(decoded_data, addr, client_ip) # DHCP OFFER
			log_update(f"DISCOVER:\n{str(data)}\n")
			log_update(f"OFFER:\n{str(resp_data)}\n")
		elif msg_type == 3:
			resp_data = dhcp_ack(decoded_data, addr, client_ip) # DHCP ACK
			log_update(f"REQUEST:\n{str(data)}\n")
			log_update(f"ACK:\n{str(resp_data)}\n")

def log_update(data):
	f = open("log_file", "a+")
	f.write(data)
	f.close()

def start():
	Thread(target=handle_client())
 
start()