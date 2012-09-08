from globals import Globals
import socket

class Communicate():
	def __init__(self):
		self.SOCKET
		pass
	
	def connect(self):
		sck = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.SOL_TCP)
		sck.connect((HOST, PORT))
		self.SOCKET = sck 
		
	def send(self, data):
		self.SOCKET.send_all(data)
	
	def read(self):
		BUFF = self.SOCKET.recv(RCV_BUFF_SZE)
		BUFF_ARY = BUFF.split("\x00")
		REMOVED = BUFF_ARY.pop(0)
		BUFF_LEN = len(BUFF_ARY)
		if BUFF_LEN is not 0:
			for val in BUFF_ARY:
				MSG_TYPE = _identify_msg_type(val)
				print MSG_TYPE
				if MSG_TYPE is 'msg':
					MSG = _pass_recived_msg(val)
					print MSG
				elif MSG_TYPE is 'account_info':
					ACC_INFO = parse_account_info(VAL)
					print ACC_INFO
				elif MSG_TYPE is 'last_seen':
					LAST_SEEN = parse_last_seen(VAL);
					print LAST_SEEN
				MSG_TYPE = ""
			print BUFF
		return BUFF
	
	def _parse_received_message(msg):
		length = msg[0:1]
		MSG['length'] = ord(length) 							# // PACKET EXCLUDING 00 AND FIRST HEX SHOULD EQUAL THIS NUMBER
		msg = msg[2:] 											#  Remove Length & F8 
		
		MSG['sec_length'] = ord(msg[0:1])
		msg = msg[5:]  											#// Remove Second Length ( 1 HEX ) , Remove XML Chrs ( 4 HEX )
		
		MSG['from_number_length'] = ord(msg[0:1]);
		msg = msg[1:] 											#Remove Length	
		MSG['from_number'] = msg[0:MSG['from_number_length']]
		msg = msg[MSG['from_number_length']:] 					#Remove NUMBER
		msg = msg[3:] 											#Remove F8 & XML ( 2 HEX )
	
		MSG['message_id_length'] = ord(msg[0:1])
		msg = msg[1:] 											# Remove Length
		MSG['message_id'] = msg[0:MSG['message_id_length']]			
		msg = msg[['message_id_length']]			
		msg = msg[4:] 											#Remove XML ( 4 HEX )
		
		MSG['timestamp_length'] = ord(msg[0:1])
		msg = msg[1:] 											#Remove Length
		MSG['timestamp'] = msg[0:MSG['timestamp_length']]
		msg = msg[MSG['timestamp_length']:]						#// Remove Timestamp
		
																#Check for Retry header 
		if msg[0,1] == "\x88":
			msg = msg[4:] 										#Remove Retry Length , i dont think i will need it
		msg = msg[9:] 											#Remove XMPP XML and Name XML Headers 
		
		MSG['sender_name_length'] = ord(msg[0:1])
		msg = msg[1:] 											#Remove Length
		MSG['sender_name'] = msg[0:MSG['sender_name_length']]			
		msg = msg[MSG['sender_name_length']:]			 		#Remove sender from msg
		
		msg = msg[9:] 											#Remove body headers
		MSG['body_txt_length'] = ord(msg[0:1])
		msg = msg[1:] 											#Remove Length
		MSG['body_txt'] = msg[0:MSG['body_txt_length']];			
		msg = msg[MSG['body_txt_length']:] 						#Remove body txt
		
		msg = msg[9:] 											#Remove XMPP XML and Name XML Headers 
		MSG['time_length'] = ord(msg[0:1]);
		msg = msg[msg:1] 										#Remove Length
		MSG['time'] = msg[0:MSG['time_length']]			
		msg = msg[['time_length']:]
		return MSG
			
	