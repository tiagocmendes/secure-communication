import asyncio
import json
import base64
import argparse
import coloredlogs, logging
import os
import getpass
import binascii
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes 
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from crypto import Crypto
logger = logging.getLogger('root')
STATE_CONNECT = 0
STATE_OPEN = 1
STATE_DATA = 2
STATE_CLOSE = 3
STATE_KEY_ROTATION=4
STATE_NEGOTIATION=5
STATE_DH=6
STATE_VALIDATE_SERVER=7


STATE_CLIENT_AUTH = 8
STATE_SERVER_AUTH = 9


class ClientProtocol(asyncio.Protocol):
    """
    Client that handles a single client
    """
    def __init__(self, file_name, loop):
        """
        Default constructor

        @param file_name: Name of the file to send
        @param loop: Asyncio Loop to use
        """

        self.file_name = file_name
        self.loop = loop
        self.chunk_count = 0
        self.last_pos = 0
        self.symetric_ciphers = ['ChaCha20','AES','3DES']
        self.cipher_modes = ['CBC','ECB','GCM']
        self.digest = ['SHA384','SHA256','SHA512','MD5','BLAKE2']
        self.state = STATE_CONNECT  # Initial State
        self.buffer = ''  # Buffer to receive data chunks
        self.choosen_cipher = None
        self.choosen_mode = None
        self.choosen_digest = None
        self.host_name="127.0.0.1"

        self.crypto = Crypto(self.choosen_cipher, self.choosen_mode, self.choosen_digest)

        self.encrypted_data = ''

        self.credentials = {}
        self.server_public_key = None
        self.nonce = os.urandom(16)
        self.server_nonce = None
        self.validation_type="Challenge" #Challenge or Citzent card
    
    def log_state(self, received):
        states = ['CONNECT', 'OPEN', 'DATA', 'CLOSE', 'KEY_ROTATION', 'NEGOTIATION', 'DIFFIE HELLMAN']
        logger.info("------------")
        #logger.info("State: {}".format(states[self.state]))
        logger.info("Received: {}".format(received))

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
        self.encrypted_data += secure_message['payload']

        return secure_message
    
    def send_mac(self) -> None:
        """
        Called when a secure message is sent and a MAC is necessary to check message authenticity.
        """
        self.crypto.mac_gen(base64.b64decode(self.encrypted_data))
        #logger.debug("My MAC: {}".format(self.crypto.mac))
        if self.crypto.iv is None:
            iv=''
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
        self.encrypted_data = ''

    def connection_made(self, transport) -> None:
        """
        Called when the client connects.

        @param transport: The transport stream to use for this client
        """
        self.transport = transport

        logger.debug('Connected to Server')
        logger.debug('Sending cipher algorithms')

        logger.info('Connection to Server')
        logger.info('LOGIN_REQUEST')
        
        message = {'type':'NEGOTIATION','algorithms':{'symetric_ciphers':self.symetric_ciphers,'chiper_modes':self.cipher_modes,'digest':self.digest}}
               
        #message = {'type': 'LOGIN_REQUEST', 'nonce':  base64.b64encode(self.nonce).decode()}

        #Generate a new NONCE
        self.crypto.auth_nonce=os.urandom(16)
        print(f"Nonce: {self.crypto.auth_nonce}")
        #message = {'type': 'SERVER_AUTH_REQUEST', 'nonce':  str(self.crypto.auth_nonce,'ISO-8859-1')}

       
        self._send(message)
        self.state=STATE_DH
        #self.state = STATE_LOGIN_REQ 
        #self.state = STATE_SERVER_AUTH


    def data_received(self, data: str) -> None:
        """
        Called when data is received from the server.
        Stores the data in the buffer

        @param data: The data that was received. This may not be a complete JSON message
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
        Processes a frame (JSON Object)

        @param frame: The JSON Object to process
        """
        logger.debug("Frame: {}".format(frame))

        try:
            message = json.loads(frame)
        except:
            logger.exception("Could not decode the JSON message")
            self.transport.close()
            return

        mtype = message.get('type', None)
        self.log_state(mtype)

        if mtype == 'CHALLENGE_REQUEST':
            self.process_challenge(message)
            return 
        elif mtype == 'SERVER_AUTH_RESPONSE':
            flag=self.process_server_auth(message)
            if not flag:
                message = {'type': 'SERVER_AUTH_FAILED'}
                secure_message = self.encrypt_payload(message)
                self._send(secure_message)
                self.send_mac()
            if flag:

                #Generate a new NONCE
                self.crypto.auth_nonce=os.urandom(16)

                self.state=STATE_CLIENT_AUTH
                
                message = {'type': 'LOGIN_REQUEST', 'nonce':  base64.b64encode(self.crypto.auth_nonce).decode()}
                secure_message = self.encrypt_payload(message)
                self._send(secure_message)
                self.send_mac()
            
                return 
        
        elif mtype == 'AUTH_RESPONSE':
            if message['status'] == 'SUCCESS':
                self.process_authentication(message)
            elif message['status'] == 'DENIED':
                logger.info('User authentication denied.')
            else:
                logger.info('User authentication failed.')
                self.nonce = os.urandom(16)
                message = {'type': 'LOGIN_REQUEST', 'nonce':  base64.b64encode(self.nonce).decode()}
                self._send(message)
                self.state = STATE_LOGIN_REQ 
            return
        
        elif mtype == 'FILE_REQUEST_RESPONSE':
            if message['status'] == 'PERMISSION_GRANTED':
                logger.info('Permission granted to transfer the file.')
                message = {'type':'NEGOTIATION','algorithms':{'symetric_ciphers':self.symetric_ciphers,'chiper_modes':self.cipher_modes,'digest':self.digest}}
                self._send(message)
                self.state = STATE_NEGOTIATION
            else:
                logger.info('Permission denied to transfer the file.')
            return

        elif mtype == 'OK':  # Server replied OK. We can advance the state
            if self.state == STATE_OPEN:
                logger.info("Channel open")
                
                self.send_file(self.file_name)
            elif self.state == STATE_DATA:  # Got an OK during a message transfer.
                # Reserved for future use
                pass
            else:
                logger.warning("Ignoring message from server")
            return

        elif mtype == 'ERROR':
            logger.warning("Got error from server: {}".format(message.get('data', None)))

        elif mtype=='INTEGRITY_CONTROL':
            flag=message['data']
            if flag=='True':
                self._send(self.encrypt_payload({'type': 'CLOSE'}))
                self.send_mac()
                logger.info("File transferred. Closing transport")
                self.transport.close()

        elif mtype == 'DH_PARAMETERS_RESPONSE':
            logger.debug('DH_PARAMETERS_RESPONSE')
            public_key=bytes(message['parameters']['public_key'],'ISO-8859-1')
            
            #Create shared key with the server public key
            self.crypto.create_shared_key(public_key)
            
            # Generate a symetric key
            self.crypto.symmetric_key_gen()
            logger.debug("Key: {}".format(self.crypto.symmetric_key))

            if self.state==STATE_KEY_ROTATION:
                self.state = STATE_OPEN
                self.send_file(self.file_name)
                
            elif self.state==STATE_DH:

                #message = {'type': 'LOGIN_REQUEST', 'nonce':  base64.b64encode(self.nonce).decode()}

                #Generate a new NONCE
                self.crypto.auth_nonce=os.urandom(16)
                print(f"Nonce: {self.crypto.auth_nonce}")
                message = {'type': 'SERVER_AUTH_REQUEST', 'nonce':  str(self.crypto.auth_nonce,'ISO-8859-1')}
                secure_message = self.encrypt_payload(message)
                self._send(secure_message)
                self.send_mac()
                self.state = STATE_SERVER_AUTH
            
                #self._send(message)
                #self.state=STATE_DH
                #self.state = STATE_LOGIN_REQ 
                #self.state = STATE_SERVER_AUTH    
                
                
                '''secure_message = self.encrypt_payload({'type': 'OPEN', 'file_name': self.file_name})
                self._send(secure_message)
                self.send_mac()
                self.state = STATE_OPEN'''

            return

        elif mtype == 'NEGOTIATION_RESPONSE':
            logger.debug("Negotiation response")

            # Receive the choosen algorithms by the server 
            self.process_negotiation_response(message)

            # Generate Diffie Helman client private and public keys
            bytes_public_key,p,g,y=self.crypto.diffie_helman_client()
            
            message = {'type':'DH_PARAMETERS','parameters':{'p':p,'g':g,'public_key':str(bytes_public_key,'ISO-8859-1')}}
            self._send(message)
            self.state=STATE_DH
            
            return


        
    

        else:
            logger.warning("Invalid message type")

        logger.debug('Closing')
        self.transport.close()
        self.loop.stop()

    def process_server_auth(self, message):
        self.crypto.signature = bytes(message['signature'], 'ISO-8859-1')
        server_cert_filename=message['server_cert']
        server_ca_cert_folder=message['server_roots']


        self.crypto.server_cert=self.crypto.load_cert(server_cert_filename)
        self.crypto.server_public_key=self.crypto.server_cert.public_key()

        # Validate server signature
        flag1=self.crypto.rsa_signature_verification(self.crypto.signature,self.crypto.auth_nonce,self.crypto.server_public_key)
        logger.info(f'Server signature validation: {flag1}')

        #Validate common name
        flag2=self.host_name==self.crypto.get_common_name(self.crypto.server_cert)
        logger.info(f'Server common_name validation: {flag2}')

        #Validate chain
        flag3=self.crypto.validate_chain(self.crypto.server_cert,server_ca_cert_folder)

        logger.info(f'Server chain validation: {flag3}')

        if flag1 and flag2 and flag3:
            logger.info("Server validated")
            return True
        else:
            return False

    def process_authentication(self, message):
        logger.info('User authenticated with success! Username: ' + message['username'])

        secure_message = self.encrypt_payload({'type': 'OPEN', 'file_name': self.file_name})
        self._send(secure_message)
        self.send_mac()
        self.state = STATE_OPEN
         
    
    def process_challenge(self, message):
        self.credentials['username'] = input("Username: ")
        self.credentials['password'] = getpass.getpass("Password: ")

        self.server_nonce = str(base64.b64decode(message['nonce'].encode()))
        self.encrypted_password = self.crypto.rsa_encryption(str(self.crypto.auth_nonce) + self.credentials['password'] + self.server_nonce, self.crypto.server_public_key)
        
        message['type'] = 'CHALLENGE_RESPONSE'
        message['credentials'] = {}
        message['credentials']['username'] = self.credentials['username']
        message['credentials']['encrypted_password'] = base64.b64encode(self.encrypted_password).decode()
        self._send(message)

            # IMPORTANTE PARA O SERVER print(self.crypto.rsa_decryption(self.encrypted_password, base64.b64decode(message['private_key'].encode())))
        return 

    def process_negotiation_response(self, message: str) -> bool:
        """
        Called when a response of type NEGOTIATION is received.

        @param message: Received message
        """
        logger.debug("Process Negotiation: {}".format(message))

        self.crypto.symmetric_cipher=message['chosen_algorithms']['symetric_cipher']
        self.crypto.cipher_mode=message['chosen_algorithms']['chiper_mode']
        self.crypto.digest=message['chosen_algorithms']['digest']

        logger.info("Choosen algorithms: {} {} {}".format(self.crypto.symmetric_cipher,self.crypto.cipher_mode,self.crypto.digest))
		
    def connection_lost(self, exc):
        """
        Connection was lost for some reason.
        @param exc:
        """
        logger.info('The server closed the connection')
        self.loop.stop()

    def send_file(self, file_name: str) -> None:
        """
        Sends a file to the server.
        The file is read in chunks, encoded to Base64 and sent as part of a DATA JSON message
        @param file_name: File to send
        """

        with open(file_name, 'rb') as f:
            message = {'type': 'DATA', 'data': None}
            file_ended = False
            read_size = 16 * 60 
            while True:
                if self.last_pos != 0:
                    f.seek(self.last_pos)
                    self.last_pos=0

                if self.chunk_count==1000:
                    self.state=STATE_KEY_ROTATION

                    #Generate Diffie Helman client private and public keys
                    bytes_public_key,p,g,y=self.crypto.diffie_helman_client()
                    message={'type':'DH_PARAMETERS','parameters':{'p':p,'g':g,'public_key':str(bytes_public_key,'ISO-8859-1')}}
                    self.chunk_count=0
                    self.last_pos=f.tell()
                    self._send(message)
                    break

                self.chunk_count+=1
                
                data = f.read(16 * 60)
                message['data'] = base64.b64encode(data).decode()
                #logger.debug("Data: {} read size {}".format(data,f.tell()))
                secure_message = self.encrypt_payload(message)
                
                self._send(secure_message)
                self.send_mac()
                
                if len(data) != read_size:
                    file_ended=True
                    break
            
            # When it ends create MAC
            if file_ended:
                self._send(self.encrypt_payload({'type': 'CLOSE'}))
                self.send_mac()
                logger.info("File transferred. Closing transport")
                self.transport.close()
        
    def _send(self, message: str) -> None:
        """
        Effectively encodes and sends a message
        :param message:
        :return:
        """
        logger.info("Send: {}".format(message['type']))
        logger.debug("Send: {}".format(message))

        message_b = (json.dumps(message) + '\r\n').encode()
        self.transport.write(message_b)

def main():
    parser = argparse.ArgumentParser(description='Sends files to servers.')
    parser.add_argument('-v', action='count', dest='verbose',
                        help='Shows debug messages',
                        default=0)
    parser.add_argument('-s', type=str, nargs=1, dest='server', default='127.0.0.1',
                        help='Server address (default=127.0.0.1)')
    parser.add_argument('-p', type=int, nargs=1,
                        dest='port', default=5000,
                        help='Server port (default=5000)')

    parser.add_argument(type=str, dest='file_name', help='File to send')

    args = parser.parse_args()
    file_name = os.path.abspath(args.file_name)
    level = logging.DEBUG if args.verbose > 0 else logging.INFO

    port = args.port
    server = args.server

    coloredlogs.install(level)
    logger.setLevel(level)

    logger.info("Sending file: {} to {}:{} LogLevel: {}".format(file_name, server, port, level))

    loop = asyncio.get_event_loop()
    coro = loop.create_connection(lambda: ClientProtocol(file_name, loop),
                                  server, port)
    loop.run_until_complete(coro)
    loop.run_forever()
    loop.close()

if __name__ == '__main__':
    main()