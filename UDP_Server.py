import socket as s
import time as t
import netifaces as ni
import struct

serverIP = ""
serverPort = 67

server = s.socket(s.AF_INET, s.SOCK_DGRAM)
server.setsockopt(s.SOL_SOCKET, s.SO_REUSEPORT, 1)
server.setsockopt(s.SOL_SOCKET, s.SO_BROADCAST, 1) # Broadcast
server.bind((serverIP, serverPort))
print("server (" +  serverIP + "," + str(serverPort) + ") ready")

ni.ifaddresses('enp0s3')
your_ip = ni.ifaddresses('enp0s3')[ni.AF_INET][0]['addr']
print(f"Own IP: {your_ip}\n")

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

def dhcp_offer(data, addr):
	"""
	Function to send response.
	"""
	
	value = {}
	value[dhcp_format[0]['field']] = b'\x02' #op_code
	value[dhcp_format[1]['field']] = b'\x01' #htype
	value[dhcp_format[2]['field']] = b'\x06' #hlen
	value[dhcp_format[3]['field']] = b'\x00' #hops
	value[dhcp_format[4]['field']] = b'\x01\x05\x08\x09' #xid
	value[dhcp_format[5]['field']] = b'\x00\x00' #secs
	value[dhcp_format[6]['field']] = b'\x00\x00' #flags
	value[dhcp_format[7]['field']] = s.inet_aton('192.168.1.50') #ciaddr
	value[dhcp_format[8]['field']] = s.inet_aton(your_ip) #yiaddr
	value[dhcp_format[9]['field']] = s.inet_aton(your_ip) #siaddr
	value[dhcp_format[10]['field']] = data[10]['giaddr'] #giaddr
	value[dhcp_format[11]['field']] = data[11]['chaddr'] #chaddr
	value[dhcp_format[12]['field']] = bytearray(64) #sname
	value[dhcp_format[13]['field']] = bytearray(128) #file
	
	magic_cookie = s.inet_aton('99.130.83.99')
	DHCPOptions1 = bytes([53 , 1 , 2]) # => option 53, length 1, DHCP Offer
	"""
	DHCPOptions2 = bytes([3, 4]) + s.inet_aton('255.255.255.0') #Subnet mask
	DHCPOptions3 = bytes([3 , 4]) + s.inet_aton('192.168.1.1') #192.168.1.1 router
	DHCPOptions4 = bytes([51 , 4 , 0x00, 0x01, 0x51, 0x80]) # 86400s IP lease time
	DHCPOptions5 = bytes([54 , 4 , 0xC0, 0xA8, 0x01, 0x01]) # DHCP server
	"""
	data_to_send = b""

	for val in value.values():
		data_to_send += val
	
	data_to_send += magic_cookie
	data_to_send += DHCPOptions1
	#data_to_send += DHCPOptions2
	#data_to_send += DHCPOptions3
	#data_to_send += DHCPOptions4
	#data_to_send += DHCPOptions5
	data_to_send += bytes([255])
	
	print(f"Data to send:{data_to_send}\n")
	print(f"Data send to:{addr}")
	server.sendto(data_to_send, ('255.255.255.255', 68))
	server.sendto(data_to_send, addr)
	print("Data sent!\n")
	
def start():
	while True:
		data, addr = server.recvfrom(2048) #DHCP DISCOVER
		print(f"Server has received:\n{data}\n")
		
		decoded_data = data_decoder(data)
		print(f"{decoded_data}\n")
		
		dhcp_offer(decoded_data, addr) #DHCP OFFER
start()