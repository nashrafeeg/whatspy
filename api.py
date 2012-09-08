import socket
import uuid
import struct
import md5


class Communicate():
	def __init__(self):
		self.SOCKET
		self.SERVER = 's.whatsapp.net'
		self.HOST = 'bin-short.whatsapp.net'
		self.PORT = '5222'
		self.RCV_BUFF_SZE = 1024
		self.DIGEST_URI = 'xmpp/s.whatsapp.net'
		self.REALM = 's.whatsapp.net'
		self.QOP = 'auth'
		self.CONTENT_IDENTIFIER = 'STREAM_CLIENT_PERSISTENT' 
		self.MSG_IDENTIFIER = "\x5D\x38\xFA\xFC"		
		self.SERVER_DELIVERY_IDENTIFIER = "\x8C"		
		self.CLENT_DELEVERY_IDENTIFIER = "\x7f\xbd\xad"
		self.ACC_INFO_INDENT = "\x99\xBD\xA7\x94"		
		self.LAST_SEEN_IDENT = "\x48\x38\xFA\xFC"
		self.LAST_SEEN_IDENT2 = "\x7B\xBD\x4C\x8B"
		self.LOGIN_DATA = "WA"+"\x00\x04\x00\x19\xf8\x05\x01\xa0\x8a\x84\xfc\x11"+"iPhone-2.6.9-5222" 
		self.LOGIN_DATA = LOGIN_DATA +"""\x00\x08\xf8\x02\x96\xf8\x01\xf8\x01\x7e\x00\x07\xf8
									\x05\x0f\x5a\x2a\xbd\xa7"""
		self.NUMBER
		self.PASSWORD
		
	def setup_credential(self, user, IMEI):
		self.NUMBER = user
		self.PASSWORD = self._password_from_imei(IMEI)
	
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
					MSG = _pars_recived_msg(val)
					print MSG
				elif MSG_TYPE is 'account_info':
					ACC_INFO = _parse_account_info(VAL)
					print ACC_INFO
				elif MSG_TYPE is 'last_seen':
					LAST_SEEN = _parse_last_seen(VAL);
					print LAST_SEEN
				MSG_TYPE = ""
			print BUFF
		return BUFF
	
	def _parse_received_message(self, msg):
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
		
	def _parse_account_info(msg):
		msg = msg[3:] 		
		msg = msg[4:] 		#Remove Success XML
		#Next should be status
		
		acst = msg[0:1];	
		if acst == "\x09":
			ACCOUNT_STATUS = 'active'
		else:
			ACCOUNT_STATUS = 'inactive'
			
		msg = msg[2:] 		#Remove status & KIND XML
		
		actkind = msg[0:1]
		if actkind == "\x37":
			ACCOUNT_KIND = 'free';
		else:
			ACCOUNT_KIND = 'paid';
		msg = msg[3:] 		#Remove XML
		
		creation_timstamp_len = ord(msg[0:1]) #Should return 10 for the next few thousdands years
		msg = msg[1:] 		#Remove Length
		ACCOUNT_CREATION = msg[0:creation_timstamp_len]	
		msg = msg[creation_timstamp_len:] 		#remove Timestamp
		
		msg = msg[2:] 		#Remove Expiration XML
		expr_length = ord(msg[0:1]) #Should also be 10
		msg = msg[1:] 		#Remove Length
		ACCOUNT_EXPIRATION =msg[0:expr_length]	
		
		ACCOUNT_INFO ['status'] = ACCOUNT_STATUS
		ACCOUNT_INFO['kind'] = ACCOUNT_KIND
		ACCOUNT_INFO['creation'] = ACCOUNT_CREATION
		ACCOUNT_INFO['expiration'] = ACCOUNT_EXPIRATION
		return ACCOUNT_INFO
	
	def _parse_last_seen(self):
		msg = msg[7:] 		# Remove Some XML DATA
		
		moblen = ord(msg[0:1]); 
		msg = msg[1:] 		# Remove Length
		lastseen['mobile'] = msg[0:moblen]	
		msg = msg[moblen:]
		msg = msg[16:] 		# Remove Some More XML DATA
		
		last_seen_len = ord(msg[0:1]) 
		msg = msg[1:] 		# Remove Length
		lastseen['seconds_ago'] = msg[0:last_seen_len]	
		return lastseen
	
	def login(self):
		self.send(LOGIN_DATA)
		Buffer = self.SOCKET.read()
		Response = Buffer[26:].decode('base64')
		arrResp = Response.split(',')
		authData = {}
		for val in arrResp:
			resData = val.split('=')
			authData[ resData[0] ] = resData[1].split('"')[1]

		ResData = self._authenticate( authData['nonce'] )
		Response = "\x01\x31\xf8\x04\x86\xbd\xa7\xfd\x00\x01\x28" + ResData.encode('base64')
		self.send(Response)
		rBuffer =self.read()
		self.read()
		#this packet contains the name need to find a way to encode the name proper 
		next = "\x00\x12\xf8\x05\x74\xa2\xa3\x61\xfc\x0a\x41\x68\x6d\x65\x64\x20\x4d\x6f\x68\x64\x00\x15\xf8\x06\x48\x43\x05\xa2\x3a\xf8\x01\xf8\x04\x7b\xbd\x4d\xf8\x01\xf8\x03\x55\x61\x24\x00\x12\xf8\x08\x48\x43\xfc\x01\x32\xa2\x3a\xa0\x8a\xf8\x01\xf8\x03\x1f\xbd\xb1";
		stream = self.send(next)
		self.read()
		
	def authenticate(self, nonce, _NC = '00000001'):
		# TODO: FIX THIS BLOODY MESS i mean really wtf.....
		cnonce = str(uuid.uuid4())
		a1 = '%s:%s:%s' % (self.NUMBER, self.SERVER, self.PASSWORD)		
		if True: #why ? 
			a1 = struct.pack('H32', md5.md5(a1).hexdigest()) + ':' + nonce + ':' + cnonce #ugly as hell gotta rewrite in more pythonic way 
		a2 = "AUTHENTICATE:" + self.DIGEST_URI
		password = md5.md5(a1).hexdigest() + ':' + nonce + ':' +_NC + ':' + cnonce + ':' . self.QOP + ':' + md5.md5(a2).hexdigest()
		password = md5.md5(password).hexdigest()
		Response = 'username=%s,realm=%s,nonce=%s,cnonce=%s,nc=%s,qop=%s,digest-uri=%s,response=%s,charset=utf-8' % (self.NUMBER, self.REALM, nonce, cnonce, _NC, self.QOP, self.DIGEST_URI, password)	
		return Response
		
		