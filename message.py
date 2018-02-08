import utils
import time
import random
import hashlib
import struct
class BTCMessage:
	def makeMessage(command, payload):
		magic = 0xD9B4BEF9 # TestNet
		checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[0:4]
		return struct.pack('L12sL4s', magic, command, len(payload), checksum) + payload
	makeMessage = staticmethod(makeMessage)
	def pongMessage(nonce):
		return BTCMessage.makeMessage('pong', nonce)
	pongMessage = staticmethod(pongMessage)
	def verackMessage():
		return BTCMessage.makeMessage('verack', '')
	verackMessage = staticmethod(verackMessage)
	def versionMessage():
		version = 60002
		services = 1
		timestamp = int(time.time())
		local = utils.BTCnetaddr(addr='73.116.5.231', port=8333)
		remote = utils.BTCnetaddr(addr='73.116.5.231', port=8333)
		start_height = 0
		nonce = random.getrandbits(64)
		subVersion = utils.BTCvarstr('').varstr()
		payload = struct.pack('<LQQ26s26sQsL', version, services, timestamp, local.netaddr(), remote.netaddr(), nonce, subVersion, start_height)
		return BTCMessage.makeMessage('version', payload)
	versionMessage = staticmethod(versionMessage)
	def txMessage(tx):
		return BTCMessage.makeMessage('tx', tx.packed())
	txMessage = staticmethod(txMessage)
	def invMessage(invs):
		msg = ''
		msg += utils.BTCvarint(len(invs)).packed()
		for inv in invs:
			msg += inv.packed()
		return BTCMessage.makeMessage('inv', msg)
	invMessage = staticmethod(invMessage)
	def getDataMessage(invs):
		msg = ''
		msg += utils.BTCvarint(len(invs)).packed()
		for inv in invs:
			msg += inv.packed()
		return BTCMessage.makeMessage('getdata', msg)
	getDataMessage = staticmethod(getDataMessage)
	def getBlocksMessage(blocks, stop=struct.pack('32s', '\0' * 32)):
		msg = ''
		msg += utils.BTCvarint(len(blocks)).packed()
		for block in blocks:
			msg += struct.pack('32s', block)
		msg += stop
		return BTCMessage.makeMessage('getBlocks', msg)
	getBlocksMessage = staticmethod(getBlocksMessage)
	def getHeadersMessage(headers, stop=struct.pack('32s', '\0' * 32)):
		msg = ''
		msg += struct.pack('<L', 60002)
		msg += utils.BTCvarint(len(headers)).packed()
		for header in headers:
			msg += struct.pack('32s', header)
		msg += stop
		return BTCMessage.makeMessage('getheaders', msg)
	getHeadersMessage = staticmethod(getHeadersMessage)
