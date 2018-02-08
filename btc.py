#!/usr/bin/python 
import base58
import os
from dns import resolver
import ecdsa
import time
import binascii
import random
import hashlib
import struct
import utils
import socket
import select
from peer import BTCPeer
from message import BTCMessage
import crypto
class BTCNode:
	isMining = False
	current_block = None
	inputs = []
	peers = []
	newHashes = []
	relaySet = dict()
	def __init__(self):
		self.peers = []
	def dataRejected(self, peer, rejection):
		kind, code, reason, other = rejection

		print(">> REJECT - %s %s" % (peer.name, reason))
		if other in self.relaySet:
			self.relaySet.pop(other, None)
	def invsReceived(self, peer, invs):
		request_invs = []
		for inv in invs:
			if inv.invType == 2 and self.current_block == None:
				print("New Block Available: %s" % (binascii.hexlify(inv.invHash[::-1])))
				peer.socket.send(BTCMessage.getDataMessage([inv]))
			elif inv.invHash not in self.relaySet:
				request_invs.append(inv)
		if len(request_invs) > 0:
			peer.socket.send(BTCMessage.getDataMessage(request_invs))

	def invsRequested(self, peer, invs):
		for inv in invs:
			if inv.invType == 1 and inv.invHash in self.relaySet:
				tx = self.relaySet[inv.invHash]
				txHash = binascii.hexlify(tx.hash()[::-1])
				peer.socket.send(BTCMessage.txMessage(tx))

	def txReceived(self, peer, tx):
		if tx.hash() not in self.relaySet:
			self.relaySet[tx.hash()] = tx
			print("Relay set count: %i" % len(self.relaySet))
			newInv = utils.BTCinv(1, tx.hash())
			self.newHashes.append(newInv)
			print(tx.txins[-1].decodeScriptSig())
	def blockReceived(self, peer, block):
		print("%s - [New Block - Merkle: %s Previous: %s TxnCount: %i" % (peer.socket.getpeername()[0], binascii.hexlify(block.merkle_root), binascii.hexlify(block.previous_block), block.txn_count.value))
		self.current_block = block
		print(binascii.hexlify(self.current_block.merkleRoot()))
		self.isMining = True
	def headersReceived(self, peer, headers):
		return

	def headersRequested(self, peer, headers):
		print("%s - [Requested %i headers] " %  (peer.socket.getpeername()[0], len(headers)))

	def connectionFailed(self, peer):
		print("%s - Peer connection failed" % (peer.name))
		if(peer.socket in self.inputs):
			self.inputs.remove(peer.socket)
		if(peer in self.peers):
			self.peers.remove(peer)

	def connectPeers(self, peers):
		for peer in peers:
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			sock.settimeout(3)
			p = peer.to_text().rstrip()
			try:
				sock.connect((p, 8333))
			except:
				continue
			self.inputs.append(sock)
			btc_peer = BTCPeer(sock, self)
			self.peers.append(btc_peer)
			sock.send(BTCMessage.versionMessage())
	def run(self):
		while len(self.inputs) > 0 and (self.isMining == False and self.current_block == None):
			readable, writable, exceptional = select.select(self.inputs, [], self.inputs)
			for s in readable:
				for peer in self.peers:
					if(peer.socket == s):
						peer.parseDataFrame()
			for e in exceptional:
				print("+++ EXCEPTION +++")
				inputs -= e
			if len(self.newHashes) > 0:
				for peer in self.peers:
					try:
						peer.socket.send(BTCMessage.invMessage(self.newHashes))
					except Exception as e:
						print(e)
						self.connectionFailed(peer)
				self.newHashes = []
		if(self.isMining == True):
			print("Starting miner...")
			current_header = utils.BTCheader(self.current_block.version, self.current_block.previous_block, self.current_block.merkle_root, self.current_block.timestamp, self.current_block.bits, self.current_block.nonce, self.current_block.txn_count)

			hashes = self.relaySet.keys()
			txs = self.relaySet.values()
			merkle = utils.merkleRoot(hashes)
			start = time.time()
			hashes = 0
			while True:
				hashes = hashes + 1
				nonce = random.getrandbits(32)
				block = utils.BTCheader(self.current_block.version, current_header.hash(), merkle, time.time(), self.current_block.bits, nonce, len(txs))
				if(hashes % 100000 == 0):
					print(binascii.hexlify(block.hash())[::-1])
					end = time.time()
					print("Hash rate: %f" % (hashes / (end - start)))
peers = resolver.query('seed.bitcoin.sipa.be', 'A')
print("Got %i peers from DNS" % (len(peers)))
print("Connecting to peers...")
node = BTCNode()
node.connectPeers(peers)
node.run()
