import socket as s
import time as t

serverIP = ""
serverPort = 67

server = s.socket(s.AF_INET, s.SOCK_DGRAM)
#server.setsockopt(s.SOL_SOCKET, s.SO_REUSEPORT, 1)
#server.setsockopt(s.SOL_SOCKET, s.SO_BROADCAST, 1) # Broadcast
server.bind((serverIP, serverPort))
print("server (" +  serverIP + "," + str(serverPort) + ") ready")

"""
DHCP Format length in byte.
"""
dhcp_format=[
	{'field':'op_code', 'name':'operation_code', 'length':1, 'type':int},
	{'field':'htype', 'name':'hardware_type', 'length':1, 'type':int},
	{'field':'hlen', 'name':'hardware_address_length', 'length':1, 'type':int},
	{'field':'hops', 'name':'hops', 'length':1, 'type':int},
	{'field':'xid', 'name':'transaction_identifier', 'length':4, 'type':hex},
	{'field':'secs', 'name':'seconds', 'length':2, 'type':int},
	{'field':'flags', 'name':'flags', 'length':2, 'type':hex},
	{'field':'ciaddr', 'name':'client_ip_address', 'length':4, 'type':str},
	{'field':'yiaddr', 'name':'your_ip_address', 'length':4, 'type':str},
	{'field':'siaddr', 'name':'server_ip_address', 'length':4, 'type':str},
	{'field':'giaddr', 'name':'gateway_ip_address', 'length':4, 'type':str},
	{'field':'chaddr', 'name':'client_hardware_address', 'length':16, 'type':str},
	{'field':'sname', 'name':'server_name', 'length':64, 'type':int},
	{'field':'file', 'name':'boot_file_name', 'length':128, 'type':int},
	{'field':'options', 'name':'options', 'length':0, 'type':int}
]

def message_decode(data):
	"""
	Function to decode data depending on dhcp_format.
	"""

def start():
	while True:
		data, addr = server.recvfrom(2048)
		print(f"Server has received:\n{message_decode(data)}\n")

start()