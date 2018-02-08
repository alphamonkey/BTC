import utils
import struct
import socket
import hashlib
from message import BTCMessage

class BTCPeer:
	buffer = ''
	def __init__(self, socket, node):
		self.socket = socket
		self.node = node
		self.name = self.socket.getpeername()[0]
	def parseDataFrame(self):
		try:
			header = self.socket.recv(24)
		except:
			self.node.connectionFailed(self)
			return
		if(len(header) != 24):
			return 
		(magic, command, length, checksum) = struct.unpack('L12sL4s', header)
		if(magic == 0xD9B4BEF9):
			remainingBytes = length
			while(remainingBytes > 0):
				newBytes = self.socket.recv(remainingBytes)
				self.buffer += newBytes
				remainingBytes -= len(newBytes)

			if self.validateChecksum(checksum) == True:
				payload = self.buffer
				self.buffer = ''
				self.handleCommand(command.rstrip('\0'), length, payload)

			else:
				print("!! %s Checksum failed: [Cmd: %s ExpectedLen: %i BufLen: %i]" % (self.socket.getpeername()[0], command, length, len(self.buffer)))
				self.buffer = ''


	def validateChecksum(self, checksum):
		my_checksum = hashlib.sha256(hashlib.sha256(self.buffer).digest()).digest()[0:4]
		if checksum == my_checksum:
			return True
		return False

	def handleCommand(self, command, length, payload):
		if(command == 'verack'):
			print("%s - [Version Acknowledged]" % (self.socket.getpeername()[0]))
			self.socket.send(BTCMessage.verackMessage())
		elif(command == 'reject'):
			self.node.dataRejected(self, utils.parseRejectMessage(payload))
		elif(command == 'getdata'):
			invs = utils.parseGetDataMessage(payload)
			self.node.invsRequested(self, invs)
		elif(command == 'version'):
			print("%s - [Version Received]" % (self.socket.getpeername()[0]))
			self.socket.send(BTCMessage.verackMessage())
			#self.socket.send(BTCMessage.getHeadersMessage())
		elif(command == 'getheaders'):
			headers = utils.parseGetHeadersMessage(payload)
			self.node.headersRequested(self, headers)
		elif(command == 'headers'):
			headers = utils.parseHeadersMessage(payload)
			self.node.headersReceived(self, headers)
		elif(command == 'ping'):
			self.socket.send(BTCMessage.pongMessage(payload))
		elif(command == 'addr'):
			addrs = utils.parseAddrMessage(payload)
		elif(command == 'inv'):
			invs = utils.parseInvMessage(payload)
			self.node.invsReceived(self, invs)
		elif(command == 'block'):
			block = utils.BTCblock.from_data(payload)
			self.node.blockReceived(self, block)
		elif(command == 'tx'):
			tx = utils.BTCtx.from_data(payload)
			self.node.txReceived(self, tx)
		elif(command != 'alert'):
			print(command)

