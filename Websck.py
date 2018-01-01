import socket
import base64
import struct
import threading
import time
from select import select
from hashlib import sha1

class ClientHandler(threading.Thread):
	def __init__(self, sock, addr, origin = ''):
		threading.Thread.__init__(self)
		self.origin = origin
		self.sock = sock
		self.addr = addr
		self.protocol = ''
		self.message = ['']
		self.closed = False

	#handsacking return protocol
	def handsacking(self):
		req = self.sock.recv(1024)
		header_end = req.find("\r\n\r\n")
		if header_end != -1:
			header = req[:header_end]
			header_lines = header.split("\r\n")
			headers = {}
			print header_lines[0]
			for line in header_lines[1:]:
				key, value = line.split(": ")
				headers[key] = value
			if self.origin == "" or self.origin == headers["origin"] :
				self.sock.send("HTTP/1.1 101 Web Socket Protocol Handshake\r\n")
				self.sock.send("Upgrade: WebSocket\r\n")
				self.sock.send("Connection: Upgrade\r\n")
				self.sock.send("Sec-WebSocket-Accept: %s\r\n" % self.hashKey(headers["Sec-WebSocket-Key"]))
				if headers.has_key("Sec-WebSocket-Protocol"):
					self.sock.send("Sec-WebSocket-Protocol: "+headers["Sec-WebSocket-Protocol"]+"\r\n")
				self.sock.send("Server: TestTest\r\n")
				self.sock.send("origin: http://localhost\r\n")
				self.sock.send("Access-Control-Allow-Credentials: true\r\n")
				self.sock.send("\r\n")
				if headers.has_key("Sec-WebSocket-Protocol") and headers["Sec-WebSocket-Protocol"] != "":
					return headers["Sec-WebSocket-Protocol"]
				else:
					return True
			else:
				sock.send("HTTP/1.1 400 Web Socket Protocol Handshake\r\n")
				sock.send("\r\n")
				sock.close()
				return False
		else:
			return False

	def hashKey(self, key):
		guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
		combined = key + guid
		hashed = sha1(combined).digest()
		result = base64.b64encode(hashed)
		return result
	
	def decodeMessage(self, data):
		if len(self.message) != 3:
			self.message[0] += data
			data = self.message[0]
			lid = len(data)
			
			if ord(data[0]) == 136:
				self.close()
				return
			if lid < 6: # 1 + 1 + 4 (? + l_data + mask)
				return
			datalength = ord(data[1]) & 127
			mask_index = 2

			if datalength == 126:
				if lid < 8:
					return
				mask_index = 4
				datalength = struct.unpack(">H", data[2:4])[0]
			elif datalength == 127:	
				if lid < 14:
					return
				mask_index = 10
				datalength = struct.unpack(">Q", data[2:10])[0]
			self.message = [datalength, data[mask_index:mask_index+4], data[mask_index+4:]]
		else:
			self.message[2] += data
		
		if len(self.message[2]) < self.message[0]:
			return
		
		# Extract masks
		masks = [ord(m) for m in self.message[1]]
		msg = ''
		j = 0
		# Loop through each byte that was received
		for i in range(self.message[0]):
			# Unmask this byte and add to the decoded buffer
			msg += chr(ord(self.message[2][i]) ^ masks[j])
			j += 1
			if j == 4:
				j = 0
				
		self.onMessage(msg)
		if self.message[2][self.message[0]:] == '':
			self.message = ['']
		else:
			data = self.message[2][self.message[0]:]
			self.message = ['']
			self.decodeMessage(data)

	def sendMessage(self, s, binary = False):
		"""
		Encode and send a WebSocket message
		"""
		# Empty message to start with
		message = ""
		# always send an entire message as one frame (fin)
		# default text
		b1 = 0x81

		if binary:
			b1 = 0x02
		
		# in Python 2, strs are bytes and unicodes are strings
		if type(s) == unicode:
			payload = s.encode("UTF8")

		elif type(s) == str:
			payload = s
		# Append 'FIN' flag to the message
		message += chr(b1)
		# never mask frames from the server to the client
		b2 = 0

		# How long is our payload?
		length = len(payload)
		if length < 126:
			b2 |= length
			message += chr(b2)

		elif length < (2 ** 16):
			b2 |= 126
			message += chr(b2)
			l = struct.pack(">H", length)
			message += l

		else:
			l = struct.pack(">Q", length)
			b2 |= 127
			message += chr(b2)
			message += l
		# Append payload to message
		message += payload

		# Send to the client
		data = str(message)
		self.sock.send(str(message))

	def onNew(self):
		print("new protocol "+self.protocol)
		print self.addr
		self.sendMessage('wkwkwk')

	def onClose(self):
		print "closed"

	def onMessage(self, msg):
		print('MSG > ' + msg)

	def run(self):
		self.protocol = self.handsacking()
		if self.protocol:
			self.onNew()
			while not self.closed:
				data = self.sock.recv(64)
				# print [ord(m) for m in data]
				if data:
					self.decodeMessage(data)
				else:
					self.close()
	def close(self):
		self.onClose()
		self.closed = True
	def __del__(self):
		print "kok"

class Websck:
	def __init__(self, ip, port, origin = ""):
		self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.server_socket.bind((ip, port))
		self.server_socket.listen(10)
		self.origin = origin
		self.client_list = []
		self.clientClass = ClientHandler

	def setClientClass(self, clientClass):
		self.clientClass = clientClass
		
	def run(self):
		while True:
			sock, addr = self.server_socket.accept()
			client = self.clientClass(sock, addr)
			client.start()
			
	def close(self):
		self.server_socket.close()
		
if __name__ == "__main__":
	ws = Websck("127.0.0.1",5000)
	ws.run()
	ws.close()
