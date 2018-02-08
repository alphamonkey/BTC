import socket
import crypto
import struct
import time
import base58
import binascii
import hashlib
opcodes = dict()

opcodes[0x76] = "OP_DUP"
opcodes[0xa9] = "OP_HASH160"
opcodes[0x87] = "OP_EQL"
opcodes[0x88] = "OP_EQLVERIFY"
opcodes[0xac] = "OP_CHECKSIG"

def parseGetDataMessage(data):
	invs = []
	hashes_count = BTCvarint.from_data(data)
	data = data[hashes_count.size():]
	for i in range(0, hashes_count.value):
		inv = BTCinv.from_data(data)
		data = data[len(inv.packed()):]
		invs.append(inv)
	return invs

def parseHeadersMessage(data):
	headers_count = BTCvarint.from_data(data)
	data = data[1:]
	headers = []
	for i in range(0,headers_count.value):
		offset = 80 + headers_count.size()
		header = BTCheader.from_data(data[i * offset :i * offset + offset])
		headers.append(header)
	return headers
class BTCtx:
	def __init__(self, version, flags, tx_in_count, txins, tx_out_count, txouts, locktime, witness_data = None):
		self.version = version
		self.flags = flags
		self.tx_in_count = tx_in_count
		self.txins = txins
		self.tx_out_count = tx_out_count
		self.txouts = txouts
		self.locktime = locktime
		self.witness_data = witness_data
	def hash(self):
		hash = hashlib.sha256(hashlib.sha256(self.packed()).digest()).digest()
		return hash
	def packed(self):
		ret = struct.pack("<l", self.version) + self.tx_in_count.packed()
		for txin in self.txins:
			ret += txin.packed()

		ret += self.tx_out_count.packed()
		for txout in self.txouts:
			ret += txout.packed()
		ret += struct.pack("<L", self.locktime)
		return ret
		
	def from_data(data):
		flags = 0
		version = struct.unpack('<l', data[:4])[0]
		if(data[4] == 0 and data[5] == 1):
			flags = 2
		
		txins = []
		txouts = []
		if(flags == 2):
			print(">>>> Flagged tx <<<<<")
			data = data[6:]
			tx_in_count = BTCvarint.from_data(data)
			print("Input Count: %i" % (tx_in_count.value))
			data = data[tx_in_count.size():]
			for i in range (0, tx_in_count.value):
				txin = BTCtxin.from_data(data)
				data = data[txin.size():]
				txins.append(txin)
			tx_out_count = BTCvarint.from_data(data)
			data = data[tx_out_count.size():]
			
			for i in range (0, tx_out_count.value):
				txout = BTCtxout.from_data(data)
				data = data[txout.size():]
				txouts.append(txout)
			witness_count = BTCvarint.from_data(data)
			witnesses = []
			for i in range (0, witness_count.value):
				length = BTCvarint.from_data(data)
				data = data[length.size():]
				witness_data = data[:length.value]
				witnesses.append(witness_data)
				data = data[length.value:]
			locktime = struct.unpack('<L', data[:4])[0]
			return BTCtx(version, flags, tx_in_count, txins, tx_out_count, txouts, locktime, witness_data = witnesses)

		elif(flags == 0):
			data = data[4:]
			tx_in_count = BTCvarint.from_data(data)
			data = data[tx_in_count.size():]
			for i in range(0,tx_in_count.value):
				txin = BTCtxin.from_data(data)
				data = data[txin.size():]
				txins.append(txin)
			tx_out_count = BTCvarint.from_data(data)
			data = data[tx_out_count.size():]

			for i in range(0, tx_out_count.value):
				txout = BTCtxout.from_data(data)
				data = data[txout.size():]
				txouts.append(txout)
			locktime = struct.unpack('<L', data[:4])[0]
			return BTCtx(version, flags, tx_in_count, txins, tx_out_count, txouts, locktime)
	from_data = staticmethod(from_data)
def parseRejectMessage(data):
	kind = BTCvarstr.from_data(data)
	code = struct.unpack('s', data[len(kind.varstr())])[0]
	bufLen = len(kind.varstr()) + 1
	reason = BTCvarstr.from_data(data[bufLen:])
	other = data[bufLen + len(reason.varstr()):]
	return (kind.value, ord(code), reason.value, other)
def parseAddrMessage(data):
	addrs = []
	addrCount = BTCvarint.from_data(data)
	for i in range(0, addrCount.value):
		addr = BTCnetaddr.from_data(data[1:31], with_timestamp=True)
		data = data[30:]
	addrs.append(addr)
	return addrs
def parseGetHeadersMessage(data):
	locatorHashes = []
	version = struct.unpack('L', data[0:4])[0]
	headerCount = BTCvarint.from_data(data[4:])
	for i in range(0, headerCount.value):
		locatorHash = struct.unpack('32s', data[5 + 32 * i:5 + 32*(i+1)])[0]
		locatorHashes.append(locatorHash)
	hash_stop = data[-32:]
	return locatorHashes
def parseInvMessage(data):
	invs = []
	invCount = BTCvarint.from_data(data)
	for i in range(0, invCount.value):
		invData = data[1:37]
		if len(invData) != 36:
			break
		inv = BTCinv.from_data(data[1:37])
		data = data[36:]
		invs.append(inv)
	return invs
class BTCheader:
	def __init__(self, version, previous_block, merkle_root, timestamp, bits, nonce, txn_count):
		self.version = version
		self.previous_block = previous_block
		self.merkle_root = merkle_root
		self.timestamp = timestamp
		self.bits = bits
		self.nonce = nonce
		self.txn_count = txn_count
	def from_data(data):
		(version, previous_block, merkle_root, timestamp, bits, nonce) = struct.unpack('<l32s32s3L', data[:80])
		txn_count = BTCvarint.from_data(data[80:])
		return BTCheader(version, previous_block, merkle_root, timestamp, bits, nonce, txn_count)
	from_data = staticmethod(from_data)
	def packedForHash(self):
		return struct.pack('<l32s32s3L', self.version, self.previous_block, self.merkle_root, self.timestamp, self.bits, self.nonce)
	def packed(self):
		return struct.pack('<l32s32s3L', self.version, self.previous_block, self.merkle_root, self.timestamp, self.bits, self.nonce) + self.txn_count.packed()
	def hash(self):
		return hashlib.sha256(hashlib.sha256(self.packedForHash()).digest()).digest()
class BTCtxin:
	def __init__(self, previous, scriptLen, scriptSig, sequence):
		self.previous=previous
		self.scriptLen = scriptLen
		self.scriptSig = scriptSig
		self.sequence = sequence
	def packed(self):
		return self.previous.packed() + self.scriptLen.packed() + self.scriptSig + struct.pack('<L', self.sequence)
	def decodeScriptSig(self):
		ret = ""
		buff = self.scriptSig
		while len(buff) > 0:
			opcode = ord(buff[0])
			if opcode >= 0x01 and opcode <= 0x4b:
				ret += "PUSHDATA %d\n" % opcode
				buff = buff[1:]
				addr = crypto.publicKeyToAddress(buff[:opcode])
				ret += "%s\n" % (addr)
				buff = buff[opcode:]
			elif opcode in opcodes:
				ret += "%s\n" % (opcodes[opcode])
				buff = buff[1:]
			else:
				print(opcode)
				buff = buff[1:]
		return ret
	def from_data(data):
		previous = BTCoutpoint.from_data(data[:36])
		scriptLen = BTCvarint.from_data(data[36:])
		fmt = '<%isL' % (scriptLen.value)
		startIndex = 36+scriptLen.size()
		endIndex = startIndex + scriptLen.value + 4
		(scriptSig, sequence) = struct.unpack(fmt, data[startIndex:endIndex])
		return BTCtxin(previous, scriptLen, scriptSig, sequence)
	from_data = staticmethod(from_data)

	def size(self):
		return 36 + self.scriptLen.value + self.scriptLen.size() + 4
class BTCtxout:
	def __init__(self, value, scriptLen, scriptPubKey):
		self.value = value
		self.scriptLen = scriptLen
		self.scriptPubKey = scriptPubKey

	def from_data(data):
		value = struct.unpack('<Q', data[:8])[0]
		scriptLen = BTCvarint.from_data(data[8:])
		scriptPubKey = data[8+scriptLen.size():8+scriptLen.size()+scriptLen.value]
		#print("OutScriptLen: %i OutScriptSize %i" % (scriptLen.value, scriptLen.size()))
		return BTCtxout(value, scriptLen, scriptPubKey)

	from_data = staticmethod(from_data)
	def packed(self):
		return struct.pack('<Q', self.value) + self.scriptLen.packed() + self.scriptPubKey

	def decodePubKey(self):
		ret = ""
		buff = self.scriptPubKey
		while len(buff) > 0:
			opcode = ord(buff[0])
			if opcode >= 0x01 and opcode <= 0x4b:
				ret += "PUSHDATA %d\n" % (opcode)
				buff = buff[1:]
				addr = base58.b58encode_check(chr(0) + buff[:opcode])
				ret += "%s\n" % (addr)
				buff = buff[opcode:]
			elif opcode in opcodes:
				ret += "%s\n" % (opcodes[opcode])
				buff = buff[1:]
			else:
				print(opcode)
				buff = buff[1:]
		return ret
	def size(self):
		return 8 + self.scriptLen.size() + self.scriptLen.value

def merkleRoot(hashes):
	retHashes = []
	if len(hashes) % 2 == 1:
		lastHash = hashes[-1]
		hashes.append(lastHash)

	for i in range(0, len(hashes) - 1, 2):
		combinedHash = hashes[i] + hashes[i + 1]
		finalHash = hashlib.sha256(hashlib.sha256(combinedHash).digest()).digest()
		retHashes.append(finalHash)
	if len(retHashes) == 1:
		return retHashes[0]
	else:
		return merkleRoot(retHashes)
		
class BTCblock:
	def __init__(self, version, previous_block, merkle_root, timestamp, bits, nonce, txn_count, txns):
		self.version = version
		self.previous_block = previous_block
		self.merkle_root = merkle_root
		self.timestamp = timestamp
		self.bits = bits
		self.nonce = nonce
		self.txn_count = txn_count
		self.txns = txns
	def merkleRoot(self):
		hashes = []
		for tx in self.txns:
			hashes.append(tx.hash())
		return merkleRoot(hashes)
	def from_data(data):
		txns = []
		(version, previous_block, merkle_root, timestamp, bits, nonce) = struct.unpack('<L32s32sLLL', data[:80])
		txn_count = BTCvarint.from_data(data[80:])
		data = data[80+txn_count.size():]
		for i in range(0, txn_count.value):
			txn = BTCtx.from_data(data)
			txns.append(txn)
			data = data[len(txn.packed()):]
		return BTCblock(version, previous_block, merkle_root, timestamp, bits, nonce, txn_count, txns)
	from_data = staticmethod(from_data)


class BTCoutpoint:
	def __init__(self, hash, index):
		self.hash = hash
		self.index = index
	def from_data(data):
		(hash, index) = struct.unpack('<32sL', data)
		return BTCoutpoint(hash, index)
	from_data = staticmethod(from_data)
	def packed(self):
		return struct.pack('<32sL', self.hash, self.index)
class BTCinv:
	def __init__(self, invType, invHash):
		self.invType = invType
		self.invHash = invHash
	def from_data(data):
		invType, invHash = struct.unpack('L32s', data[:36])
		return BTCinv(invType, invHash)
	from_data = staticmethod(from_data)
	
	def packed(self):
		return struct.pack('L32s', self.invType, self.invHash)

class BTCnetaddr:
	def __init__(self, addr, port, services = 1, timestamp = time.time()):
		self.addr = addr
		self.port = port
		self.services = services
		self.timestamp = timestamp
	def from_data(data, with_timestamp=None):
		if(with_timestamp == None):
			(services, garbage, addr, port) = struct.unpack('<Q12s', data[0:24])
			addr, port = struct.unpack('>4sH', data[24:])
			return BTCnetaddr(socket.inet_ntoa(addr), port, services)
		else:
			timestamp, services, garbage = struct.unpack('<LQ12s', data[0:24])
			addr, port = struct.unpack('>4sh', data[24:])
			return BTCnetaddr(socket.inet_ntoa(addr), port, services, timestamp)
	from_data = staticmethod(from_data)
	def netaddr(self):
		return (struct.pack('<Q12s', self.services, '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff') + struct.pack('>4sH', self.addr, self.port))
class BTCvarint:
	def __init__(self, value):
		self.value = value

	def from_data(data):
		intType = data[0]
		if ord(intType) == 253:
			(t, value) = struct.unpack('<cH', data[:3])
			return BTCvarint(value)
		elif ord(intType) == 254:
			(t, value) = struct.unpack('<cL', data[:5])
			return BTCvarint(value)
		else:
			value = struct.unpack('<B', data[0])
			return BTCvarint(value[0])
	from_data = staticmethod(from_data)
	def size(self):
		if self.value < 0xfd:
			return 1
		elif self.value <= 0xffff:
			return 3
		else:
			return 5
	def packed(self):
		if self.value < 0xfd:
			return struct.pack('<B', self.value)
		elif self.value <= 0xffff:
			return struct.pack('<cH', '\xfd', self.value)
		elif self.value < 0xffffffff:
			return struct.pack('<cL', '\xfe', self.value)
class BTCvarstr:
	def __init__(self, value):
		self.value = value
		self.length = len(value)
	def varstr(self):
		varlen = BTCvarint(len(self.value))
		return varlen.packed() + self.value
	
	def from_data(data):
		length = BTCvarint.from_data(data)
		return BTCvarstr(data[1:1 + length.value])
	from_data = staticmethod(from_data)
