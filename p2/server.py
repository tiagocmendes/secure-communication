import asyncio
import json
import base64
import argparse
import coloredlogs, logging
import re
import os
from aio_tcpserver import tcp_server
from crypto import Crypto
from cryptography.hazmat.primitives import serialization, hashes


logger = logging.getLogger('root')

STATE_CONNECT = 0
STATE_OPEN = 1
STATE_DATA = 2
STATE_CLOSE = 3
STATE_KEY_ROTATION = 4
STATE_NEGOTIATION = 5
STATE_DH = 6

STATE_SERVER_AUTH = 7
STATE_CLIENT_AUTH = 8

storage_dir = 'files'

class ClientHandler(asyncio.Protocol):
	def __init__(self, signal):
		"""
		Default constructor.
		"""
		self.signal = signal
		self.state = 0
		self.file = None
		self.file_name = None
		self.file_path = None
		self.storage_dir = storage_dir
		self.last_pos=0
		self.new_key = False
		self.buffer = ''
		self.peername = ''

		self.symetric_ciphers = ['ChaCha20','AES','3DES']
		self.cipher_modes = ['CBC','ECB','GCM']
		self.digest = ['SHA384','SHA256','SHA512','MD5','BLAKE2']
		self.choosen_cipher = None
		self.choosen_mode = None
		self.choosen_digest = None
		self.crypto = Crypto(self.choosen_cipher, self.choosen_mode, self.choosen_digest)

		self.encrypted_data = ''
		self.decrypted_data = []

		self.client_nonce = None
		self.client_public_key = None

		self.registered_users = self.load_users()
		self.authentication_tries = 0
		self.authenticated_user = None

		self.sent_encrypted_data = ''


	def load_users(self):
		"""
		Called to load a list of usernames and their respective passwords and permissions. 
		"""

		with open('./server_db/users.csv', 'r') as f:
			f.readline() # ignore header
			users = {user.replace("\n", "").split("\t")[0]:user.replace("\n", "").split("\t")[1:] for user in f}
			return users
	
	def update_users(self):
		"""
		Called to update, in persistence, the users registered in the server.
		Most of the times, this method will be called when a user has 3 incorrect login tries.
		"""

		with open('./server_db/users.csv', 'w') as f:
			f.write("Username\tPassword\tPermissions\n")
			for user in self.registered_users:
				f.write(f"{user}\t{self.registered_users[user][0]}\t{self.registered_users[user][1]}\n")


	def encrypt_payload(self, message: dict) -> None:
		"""
        Called when a secure message will be sent, in order to encrypt its payload.

        @param message: JSON message of type OPEN, DATA or CLOSE
        """

		secure_message = {'type': 'SECURE_X', 'payload': None}
		payload = json.dumps(message).encode()
		if self.crypto.cipher_mode=='GCM':
			criptogram = self.crypto.file_encryption(payload,b"HELLO")
		else:
			criptogram = self.crypto.file_encryption(payload)
		secure_message['payload'] = base64.b64encode(criptogram).decode()
		self.sent_encrypted_data += secure_message['payload']
		
		return secure_message

	def send_mac(self) -> None:
		"""
        Called when a secure message is sent and a MAC is necessary to check message authenticity.
        """
		
		self.crypto.mac_gen(base64.b64decode(self.sent_encrypted_data))
		if self.crypto.iv is None:
			iv = ''
		else:
			iv=base64.b64encode(self.crypto.iv).decode()
		
		if self.crypto.gcm_tag is None:
			tag=''
		else:
			tag=base64.b64encode(self.crypto.gcm_tag).decode()
		
		if self.crypto.nonce is None:
			nonce=''
		else:
			nonce=base64.b64encode(self.crypto.nonce).decode()
		
		message = {'type': 'MAC', 'data': base64.b64encode(self.crypto.mac).decode(), 'iv':iv,'tag':tag,'nonce':nonce}
		self._send(message)
		self.sent_encrypted_data = ''

	def connection_made(self, transport) -> None:
		"""
		Called when a client connects

		:param transport: The transport stream to use with this client
		:return:
		"""
	
		self.peername = transport.get_extra_info('peername')
		logger.info('\n\nConnection from {}'.format(self.peername))
		self.transport = transport
		self.state = STATE_CONNECT
		
	def data_received(self, data: bytes) -> None:
		"""
        Called when data is received from the client.
        Stores the data in the buffer

        :param data: The data that was received. This may not be a complete JSON message
        :return:
        """
		logger.debug('Received: {}'.format(data))

		try:
			self.buffer += data.decode()
		except:
			logger.exception('Could not decode data from client')

		idx = self.buffer.find('\r\n')

		while idx >= 0:  # While there are separators
			frame = self.buffer[:idx + 2].strip()  # Extract the JSON object
			self.buffer = self.buffer[idx + 2:]  # Removes the JSON object from the buffer
			
			self.on_frame(frame)  # Process the frame
			idx = self.buffer.find('\r\n')

		if len(self.buffer) > 4096 * 1024 * 1024:  # If buffer is larger than 4M
			logger.warning('Buffer to large')
			self.buffer = ''
			self.transport.close()


	def on_frame(self, frame: str) -> None:
		"""
		Called when a frame (JSON Object) is extracted

		:param frame: The JSON object to process
		:return:
		"""

		try:
			message = json.loads(frame)
		except:
			logger.exception("Could not decode JSON message: {}".format(frame))
			self.transport.close()
			return

		mtype = message.get('type', "").upper()
		error = None
		logger.info("Received: {}".format(mtype))

		if mtype == 'OPEN':
			if self.state == STATE_DH: # Check if state equal DH
				ret = self.process_open(message)
			else:
				self._send({'type': 'OK'})
				self.state = STATE_OPEN
				ret=True

		if mtype == 'LOGIN_REQUEST':
			ret = self.process_login_request(message)

		elif mtype == 'SERVER_AUTH_REQUEST':
			ret = self.process_server_auth(message)
			self.state=STATE_SERVER_AUTH

		elif mtype == 'CHALLENGE_RESPONSE':
			ret = self.process_challenge_response(message)
		
		elif mtype == 'FILE_REQUEST':
			ret = self.process_file_request(message)

		elif mtype == 'SECURE_X':
			self.encrypted_data += message['payload']
			ret = True

		elif mtype == 'MAC':
			
			(ret,error)= self.process_mac(message)
			
			if ret:
				iv=base64.b64decode(message['iv'])
				tag=base64.b64decode(message['tag'])
				nonce=base64.b64decode(message['nonce'])

				if iv=='':
					iv=None
				if tag=='':
					tag=None
				if nonce=='':
					nonce=None

				self.decrypted_data.append(self.crypto.decryption(base64.b64decode(self.encrypted_data.encode()),iv,tag,nonce))

				# process secure message
				self.process_secure()

		elif mtype == 'NEGOTIATION':
			logger.debug('Negotiation received')
			(ret,error) = self.process_negotiation(message)
			self.state=STATE_NEGOTIATION

		elif mtype=='DH_PARAMETERS':
			logger.debug('DH ROTATION RECEIVED')
			ret=self.process_dh_parameters(message)

			# Generate a symetric key
			self.crypto.symmetric_key_gen()
			logger.debug("Key: {}".format(self.crypto.symmetric_key))

			message={'type':'DH_PARAMETERS_RESPONSE','parameters':{'public_key':str(self.crypto.public_key,'ISO-8859-1')}}
			self._send(message)
			if self.state==STATE_DATA:
				self.state=STATE_KEY_ROTATION
			else:
				self.state=STATE_DH
			self.new_key=True

		else:
			logger.warning("Invalid message type: {}".format(message['type']))
			ret = False

		if not ret:
			try:
				self._send({'type': 'ERROR', 'message': 'See server','data':error})
			except:
				pass # Silently ignore

			logger.info("Closing transport")
			if self.file is not None:
				self.file.close()
				self.file = None

			self.state = STATE_CLOSE
			self.transport.close()

	def process_login_request(self, message):
		"""
		Called when a client attempts to authentication with a challenge-response mechanism.
		The server receives the request and sends back a challenge.
		"""
		self.state = STATE_CLIENT_AUTH
		self.client_nonce = base64.b64decode(message['nonce'].encode())
		self.crypto.auth_nonce = os.urandom(16)
		self.client_public_key = base64.b64decode(message['public_key'].encode())
		message = {'type': 'CHALLENGE_REQUEST', 'nonce': base64.b64encode(self.crypto.auth_nonce).decode()}
		secure_message = self.encrypt_payload(message)
		self._send(secure_message)
		self.send_mac()
		
		return True

	def process_card_login_request(self, message):
		"""
		Called when a client sends an authentication request with Citizen Cardship.
		The server receives the request and sends back a challenge.
		"""
		self.state = STATE_CLIENT_AUTH
		self.client_nonce = base64.b64decode(message['nonce'].encode())
		self.crypto.auth_nonce = os.urandom(16)
		message = {'type': 'CARD_LOGIN_RESPONSE', 'nonce': base64.b64encode(self.crypto.auth_nonce).decode()}
		secure_message = self.encrypt_payload(message)
		self._send(secure_message)
		self.send_mac()
		return True

	def process_server_auth(self, message):
		"""
		Called when a client attempts to verify server authenticity.
		"""
		self.crypto.server_cert=self.crypto.load_cert("server_cert/secure_server.pem")
		self.crypto.server_ca_cert=self.crypto.load_cert("server_roots/Secure_Server_CA.pem")
		self.crypto.rsa_public_key=self.crypto.server_cert.public_key()
		self.crypto.rsa_private_key=self.crypto.load_key_from_file("server_key/server_key.pem")
		nonce=base64.b64decode(message['nonce'].encode())

		# Encrypt NONCE received by client
		self.crypto.signature = self.crypto.rsa_signing(nonce, self.crypto.rsa_private_key)

		logger.info("Sending certificates for validation")
		message={'type':'SERVER_AUTH_RESPONSE','signature':base64.b64encode(self.crypto.signature).decode(),'server_cert':base64.b64encode(self.crypto.get_certificate_bytes(self.crypto.server_cert)).decode(),'server_roots':base64.b64encode(self.crypto.get_certificate_bytes(self.crypto.server_ca_cert)).decode()}
		secure_message = self.encrypt_payload(message)
		self._send(secure_message)
		self.send_mac()
		return True
	
	def process_challenge_response(self, message):
		"""
		Called when a client requests a challenge-response authentication to server.
		The server checks if the client is registered in persistence.
		Then, it verifies the signed challenge.	
		"""
		username = message['credentials']['username']
		
		if username not in self.registered_users or 'A1' not in self.registered_users[username][1]:
			logger.info("{} authenticated denied.".format(username))
			message = {'type': 'AUTH_RESPONSE', 'status': 'DENIED'}
			secure_message = self.encrypt_payload(message)
			self._send(secure_message)
			self.send_mac()
			return False

		signed_challenge = message['credentials']['signed_challenge']
		pw, permissions = self.registered_users[username][0], self.registered_users[username][1]	
		signature_verification = self.crypto.rsa_signature_verification(base64.b64decode(signed_challenge.encode()), (str(self.client_nonce) + pw + str(self.crypto.auth_nonce)).encode(), self.crypto.load_public_key(self.client_public_key))

		if signature_verification:
			logger.info("{} authenticated with success!".format(username))
			message = {'type': 'AUTH_RESPONSE', 'status': 'SUCCESS', 'username': username}
			secure_message = self.encrypt_payload(message)
			self._send(secure_message)
			self.send_mac()
			self.authenticated_user = [username, permissions]

		else:
			self.authentication_tries += 1
			if self.authentication_tries == 3:
				# remove authentication permission
				self.registered_users[username][1] = self.registered_users[username][1].replace('1', '0')
				self.update_users()
				logger.info("{} authenticated denied.".format(username))
				message = {'type': 'AUTH_RESPONSE', 'status': 'DENIED'}
				secure_message = self.encrypt_payload(message)
				self._send(secure_message)
				self.send_mac()
				return False

			logger.info("{} authenticated failed.".format(username))
			message = {'type': 'AUTH_RESPONSE', 'status': 'FAILED'}
			secure_message = self.encrypt_payload(message)
			self._send(secure_message)
			self.send_mac()
			return True
		
		return True
	
	def process_file_request(self, message):
		"""
		Called when a client asks permission to transfer a file. 
		The server checks if the claimant has permission to do the requested operation or not and
		sends back a message to the client with permission granted or denied.
		"""

		if 'T1' in self.authenticated_user[1]:
			message = {'type': 'FILE_REQUEST_RESPONSE', 'status': 'PERMISSION_GRANTED'}
			secure_message = self.encrypt_payload(message)
			self._send(secure_message)
			self.send_mac()
		else:
			message = {'type': 'FILE_REQUEST_RESPONSE', 'status': 'PERMISSION_DENIED'}
			secure_message = self.encrypt_payload(message)
			self._send(secure_message)
			self.send_mac()
			return False

		return True
		
	def process_mac(self,message: str) -> bool:
		"""
		Processes a MAC message from the client.
		It checks the authenticity/integrity of a previous received message.

		@param message: The message to process.
		"""
		logger.debug("Process MAC: {}".format(message))

		client_mac = base64.b64decode(message['data'])

		# Generate server MAC
		self.crypto.mac_gen(base64.b64decode(self.encrypted_data))
		logger.debug("Client mac: {}".format(base64.b64decode(client_mac)))
		logger.debug("Server mac: {}".format(self.crypto.mac))

		if client_mac == self.crypto.mac:
			logger.info("Integrity control: Success")
			return (True, None)
		else:
			return (False, 'Integrity control failed.')
		
	
	def process_dh_parameters(self,message: str) -> bool:
		"""
		Processes a DH_PARAMETERS message from the client.
		It computes a shared key necessary to the Diffie Helman algorithm.

		@param message: The message to process.
		"""
		logger.debug("Process DH parameters: {}".format(message))

		g = message['parameters']['g']
		p = message['parameters']['p']
		bytes_public_key = bytes(message['parameters']['public_key'], 'ISO-8859-1')

		try:
			ret = self.crypto.diffie_helman_server(p,g,bytes_public_key)
			return ret
		except:
			return False
			
	def process_negotiation(self,message: str) -> bool:
		"""
		Processes a NEGOTIATION message from the client.
		It checks which symmetric ciphers, cipher modes 
		and digest functions are available at the server.

		@param message: The message to process.
		"""
		logger.debug("Process Negotiation: {}".format(message))
		choosen_chipher = None
		choosen_mode = None
		choosen_digest = None
		flag = None

		for cipher in self.symetric_ciphers:
			if cipher in message['algorithms']['symetric_ciphers']:
				
				choosen_chipher = cipher
				break
		if choosen_chipher != 'ChaCha20':
			for cipher_mode in self.cipher_modes:
				if cipher_mode in message['algorithms']['chiper_modes']:
					if cipher_mode=='GCM' and choosen_chipher!='AES':
						continue
					choosen_mode = cipher_mode
					break
		else:
			choosen_mode=''
		
		for digest in self.digest:
			if digest in message['algorithms']['digest']:
				choosen_digest = digest
				break

		if choosen_chipher is not None and choosen_mode is not None and choosen_digest is not None:
			self.crypto.symmetric_cipher = choosen_chipher
			self.crypto.cipher_mode = choosen_mode
			self.crypto.digest = choosen_digest
			
			flag = True
		else:
			flag = False
			return (False,"Client algorithms not compatible with server algorithms")

		if flag:
			self._send({'type': 'NEGOTIATION_RESPONSE','chosen_algorithms':{'symetric_cipher':self.crypto.symmetric_cipher,'chiper_mode':self.crypto.cipher_mode,'digest':self.crypto.digest}})
			return (True,None)
		logger.debug("Choices {} {} {}".format(choosen_chipher,choosen_mode,choosen_digest))

	def process_open(self, message: str) -> bool:
		"""
		Processes an OPEN message from the client
		This message should contain the filename

		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""
		logger.debug("Process Open: {}".format(message))

		if self.state != STATE_CLIENT_AUTH:
			logger.warning("Invalid state. Discarding")
			return False

		if not 'file_name' in message:
			logger.warning("No filename in Open")
			return False

		# Only chars and letters in the filename
		file_name = re.sub(r'[^\w\.]', '', message['file_name'])
		file_path = os.path.join(self.storage_dir, file_name)
		if not os.path.exists("files"):
			try:
				os.mkdir("files")
			except:
				logger.exception("Unable to create storage directory")
				return False

		try:
			self.file = open(file_path, "wb") 
			logger.info("File open")
		except Exception:
			logger.exception("Unable to open file")
			return False

		self._send({'type': 'OK'})

		self.file_name = file_name
		self.file_path = file_path
		self.state = STATE_OPEN
		return True

	def process_data(self, message: str) -> bool:
		"""
		Processes a DATA message from the client
		This message should contain a chunk of the file

		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""
		logger.debug("Process Data: {}".format(message))

		if self.state == STATE_OPEN or self.state == STATE_KEY_ROTATION:
			self.state = STATE_DATA
			# First Packet

		elif self.state == STATE_DATA:
			# Next packets
			pass

		else:
			logger.warning("Invalid state. Discarding")
			return False

		try:
			data = message.get('data', None)
			if data is None:
				logger.debug("Invalid message. No data found")
				return False

			bdata = base64.b64decode(message['data'])
		except:
			logger.exception("Could not decode base64 content from message.data")
			return False

		try:
			logger.debug("Writing data: {}".format(bdata))
			if self.new_key:
				self.new_key = False
				self.file.seek(self.last_pos)
				self.last_pos = 0
			self.file.write(bdata)
			self.last_pos = self.file.tell()
			self.file.flush()
		except:
			logger.exception("Could not write to file")
			return False

		return True

	def process_close(self, message: str) -> bool:
		"""
		Processes a CLOSE message from the client.
		This message will trigger the termination of this session

		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""
		logger.debug("Process Close: {}".format(message))
		self.crypto.mac_gen(base64.b64decode(self.encrypted_data))
		logger.debug("My MAC: {}".format(self.crypto.mac))
		self.transport.close()
		
		if self.file is not None:
			self.file.close()
			self.file = None

		self.state = STATE_CLOSE
		return True
	
	def process_client_certificate(self, message):
		"""
		Called when a client sends his Citizen Cardship certificate to the server in order to authenticate itself.
		The server receives and validates the certificate and also a signature.
		"""
		self.crypto.client_cert = self.crypto.load_cert_bytes(base64.b64decode(message['cert'].encode()))
		self.crypto.signature = base64.b64decode(message['signature'].encode())
		username = message['credentials']['username']

		if username not in self.registered_users :
			message = {'type': 'AUTH_RESPONSE', 'status': 'DENIED'}
			secure_message = self.encrypt_payload(message)
			self._send(secure_message)
			self.send_mac()
			return False
		
		permissions = self.registered_users[username][1]
		self.authenticated_user = [username, permissions]

		client_public_key = self.crypto.client_cert.public_key()

		# Verify client signature
		flag = self.crypto.cc_signature_validation(self.crypto.signature,self.client_nonce+self.crypto.auth_nonce,client_public_key)
		logger.info(f'CC signature validation: {flag}')

		# Verify chain
		flag1 = self.crypto.validate_cc_chain(self.crypto.client_cert)
		logger.info(f'CC certificate chain validation: {flag1}')


		if flag1 and flag:
			logger.info("Client validated")
			message = {'type': 'AUTH_RESPONSE', 'status': 'SUCCESS', 'username': self.authenticated_user[0]}
			secure_message = self.encrypt_payload(message)
			self._send(secure_message)
			self.send_mac()
			return True
		else:
			message = {'type': 'AUTH_RESPONSE', 'status': 'DENIED'}
			secure_message = self.encrypt_payload(message)
			self._send(secure_message)
			self.send_mac()
			return False

	def process_secure(self):
		"""
		Processes a SECURE_X message from the client.
		It has an encrypted payload that should be decrypted.
		The payload has a JSON message that could be of type OPEN, DATA or CLOSE.
		"""
		message = json.loads(self.decrypted_data[0])
		mtype = message['type'] 
		logger.info("Process SECURE_X: {}".format(mtype))

		if mtype == 'OPEN':
			if self.state == STATE_CLIENT_AUTH:
				ret = self.process_open(message)
			else:
				self._send({'type': 'OK'})
				self.state = STATE_OPEN
				ret=True
				
		elif mtype == 'DATA':
			message = {'type': 'DATA', 'data': ''}
			for msg in self.decrypted_data:
				message['data'] += json.loads(msg)['data']
			ret = self.process_data(message)

		elif mtype == 'LOGIN_REQUEST':
			ret = self.process_login_request(message)

		elif mtype == 'CARD_LOGIN_REQUEST':
			ret = self.process_card_login_request(message)

		elif mtype == 'SERVER_AUTH_REQUEST':
			ret = self.process_server_auth(message)

		elif mtype == 'SERVER_AUTH_FAILED':
			logger.warning("Server AUTH failed.")
			ret=False

		elif mtype == 'FILE_REQUEST':
			ret = self.process_file_request(message)

		elif mtype == 'AUTH_CERTIFICATE':
			ret = self.process_client_certificate(message)
			
		elif mtype == 'CLOSE':
			ret = self.process_close(message)

		else:
			logger.warning("Invalid message type: {}".format(message['type']))
			ret = False

		if not ret:
			try:
				self._send({'type': 'ERROR', 'message': 'See server'})
			except:
				pass # Silently ignore

			logger.info("Closing transport")
			if self.file is not None:
				self.file.close()
				self.file = None

			self.state = STATE_CLOSE
			self.transport.close()

		self.encrypted_data = ''
		self.decrypted_data = []
		return True


	def _send(self, message: str) -> None:
		"""
		Effectively encodes and sends a message
		:param message:
		:return:
		"""
		logger.info("Sent: {}".format(message['type']))

		message_b = (json.dumps(message) + '\r\n').encode()
		self.transport.write(message_b)

def main():
	global storage_dir

	parser = argparse.ArgumentParser(description='Receives files from clients.')
	parser.add_argument('-v', action='count', dest='verbose',
						help='Shows debug messages (default=False)',
						default=0)
	parser.add_argument('-p', type=int, nargs=1,
						dest='port', default=5000,
						help='TCP Port to use (default=5000)')

	parser.add_argument('-d', type=str, required=False, dest='storage_dir',
						default='files',
						help='Where to store files (default=./files)')

	args = parser.parse_args()
	storage_dir = os.path.abspath(args.storage_dir)
	level = logging.DEBUG if args.verbose > 0 else logging.INFO

	port = args.port
	if port <= 0 or port > 65535:
		logger.error("Invalid port")
		return

	if port < 1024 and not os.geteuid() == 0:
		logger.error("Ports below 1024 require eUID=0 (root)")
		return

	coloredlogs.install(level)
	logger.setLevel(level)

	logger.info("Port: {} LogLevel: {} Storage: {}".format(port, level, storage_dir))
	tcp_server(ClientHandler, worker=2, port=port)


if __name__ == '__main__':
	main()

