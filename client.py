import asyncio
import json
import base64
import argparse
import coloredlogs, logging
import os
import getpass

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes 
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logger = logging.getLogger('root')

STATE_CONNECT = 0
STATE_OPEN = 1
STATE_DATA = 2
STATE_CLOSE = 3

"""
Class with several cryptography functions.
"""
class Crypto:
    """
    Default constructor

    @param symmetric_ciphers: symmetric ciphers algorithms
    @param cipher_modes: cipher_modes algorithms
    @param digest: digest algorithms
    """
    def __init__(self, symmetric_ciphers, cipher_modes, digest):
        
        self.symmetric_cipher = symmetric_ciphers
        self.cipher_mode = cipher_modes
        self.digest = digest
        self.symmetric_key=None
    
    """
    Symmetric key generation.

    It prompts the user to enter a password.
    """
    def symmetric_key_gen(self):
        
        try:
            password = getpass.getpass(prompt='Password for key: ', stream=None)
        except Exception as error:
            print('ERROR', error)
        
        password = password.encode()
        salt = os.urandom(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        
        key = kdf.derive(password)

        if self.symmetric_cipher == 'AES':
            self.symmetric_key = key[:16]
        elif self.symmetric_cipher == '3DES':
            self.symmetric_key = key[:8]
        elif self.symmetric_cipher == 'ChaCha20':
            self.symmetric_key = key[:64]
        
        #return self.symmetric_key

class ClientProtocol(asyncio.Protocol):
    """
    Client that handles a single client
    """

    def __init__(self, file_name, loop):
        """
        Default constructor
        :param file_name: Name of the file to send
        :param loop: Asyncio Loop to use
        """

        self.file_name = file_name
        self.loop = loop
        self.symetric_ciphers=['AES','3DES']
        self.cipher_modes=['ECB','CBC']
        self.digest=['SHA256','SHA384','MD5','SHA512','BLAKE2']
        self.state = STATE_CONNECT  # Initial State
        self.buffer = ''  # Buffer to receive data chunks
        self.choosen_cipher=None
        self.choosen_mode=None
        self.choosen_digest=None

        self.crypto = Crypto(self.choosen_cipher, self.choosen_mode, self.choosen_digest)

    def connection_made(self, transport) -> None:
        """
        Called when the client connects.

        :param transport: The transport stream to use for this client
        :return: No return
        """
        self.transport = transport

        logger.debug('Connected to Server')
        logger.debug('Sending cipher algorithms')

        message = {'type':'NEGOTIATION','algorithms':{'symetric_ciphers':self.symetric_ciphers,'chiper_modes':self.cipher_modes,'digest':self.digest}}

        # TODO implementar na logica mais a frente
        #message = {'type': 'OPEN', 'file_name': self.file_name} 
        self._send(message)

        self.state = STATE_OPEN


    def data_received(self, data: str) -> None:
        """
        Called when data is received from the server.
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
        Processes a frame (JSON Object)

        :param frame: The JSON Object to process
        :return:
        """

        #logger.debug("Frame: {}".format(frame))
        try:
            message = json.loads(frame)
        except:
            logger.exception("Could not decode the JSON message")
            self.transport.close()
            return

        mtype = message.get('type', None)

        if mtype == 'OK':  # Server replied OK. We can advance the state
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
            

        elif mtype == 'NEGOTIATION_RESPONSE':
            logger.info("Negotiation response")
            #Receive the choosen algorithms by the server 
            self.process_negotiation_response(message)
            #Generate a symetric key
            self.crypto.symmetric_key_gen()
            logger.debug("Key: {}".format(self.crypto.symmetric_key))
        else:
            logger.warning("Invalid message type")

        self.transport.close()
        self.loop.stop()

    def process_negotiation_response(self,message: str) -> bool:
        logger.debug("Process Negotiation: {}".format(message))

        self.crypto.symmetric_cipher=message['chosen_algorithms']['symetric_cipher']
        self.crypto.cipher_mode=message['chosen_algorithms']['chiper_mode']
        self.crypto.digest=message['chosen_algorithms']['digest']

        logger.info("Choosen algorithms: {} {} {}".format(self.crypto.symmetric_cipher,self.crypto.cipher_mode,self.crypto.digest))
		

    
    def connection_lost(self, exc):
        """
        Connection was lost for some reason.
        :param exc:
        :return:
        """
        logger.info('The server closed the connection')
        self.loop.stop()

    def send_file(self, file_name: str) -> None:
        """
        Sends a file to the server.
        The file is read in chunks, encoded to Base64 and sent as part of a DATA JSON message
        :param file_name: File to send
        :return:  None
        """

        with open(file_name, 'rb') as f:
            message = {'type': 'DATA', 'data': None}
            read_size = 16 * 60
            while True:
                data = f.read(16 * 60)
                message['data'] = base64.b64encode(data).decode()
                self._send(message)

                if len(data) != read_size:
                    break

            self._send({'type': 'CLOSE'})
            logger.info("File transferred. Closing transport")
            self.transport.close()

    def _send(self, message: str) -> None:
        """
        Effectively encodes and sends a message
        :param message:
        :return:
        """
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
    level=logging.DEBUG
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