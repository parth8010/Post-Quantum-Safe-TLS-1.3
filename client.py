
import socket
import threading
import logging
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from src.utils.logging import setup_logging
from src.config import ClientConfig
from src.tls.protocol.handshake import TLSHandshake
from src.tls.protocol.hybrid_handshake import HybridTLSHandshake
from src.tls.protocol.record_layer import TLSRecordManager
from src.utils.logging import setup_logging
from src.tls.protocol.handshake import TLSHandshake, ClientHello
from src.tls.protocol.record_layer import TLSRecordManager

class TLSClient:
    def __init__(self, server_host='localhost', server_port=8443, cipher_suite='classical'):
        self.server_host = server_host
        self.server_port = server_port
        self.cipher_suite = cipher_suite  # 'classical' or 'hybrid'
        self.connected = False
        self.socket = None
        self.tls_handshake = None
        self.record_manager_send = None
        self.record_manager_recv = None
        setup_logging()
        self.logger = logging.getLogger("TLSClient")        
        self.config = ClientConfig()
        self.logger.info(f"Using cipher suite: {cipher_suite.upper()}")
        
    def connect(self):
        """Connect to the TLS messaging server with TLS 1.3"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            self.logger.info(f"Connecting to server {self.server_host}:{self.server_port}...")
            
            # Connect to server
            self.socket.connect((self.server_host, self.server_port))
            self.connected = True
            self.logger.info("Connected to server!")
            
            # Initialize TLS
            if self.cipher_suite.lower() == 'hybrid':
                self.tls_handshake = HybridTLSHandshake(is_server=False)
                self.logger.info("Starting Hybrid PQ-Safe TLS 1.3 handshake...")
            else:
                self.tls_handshake = TLSHandshake(is_server=False)
            self.record_manager = TLSRecordManager(is_server=False)
            
            # Perform TLS handshake
            mode_str = "🔐 Hybrid PQ-Safe (X25519+ML-KEM-768)" if self.cipher_suite.lower() == 'hybrid' else "🔒 Classical (X25519)"
            self.logger.info(f"Starting TLS 1.3 handshake with {mode_str}...")
            if self._perform_tls_handshake():
                self.logger.info("TLS handshake successful! Secure connection established.")
                # Start message handling
                self._start_message_handling()
            else:
                self.logger.error("TLS handshake failed!")
                self.disconnect()
                
        except Exception as e:
            self.logger.error(f"Failed to connect: {e}")
            self.disconnect()
    
    def _perform_tls_handshake(self):
        try:
            # Create and send ClientHello
            client_hello = self.tls_handshake.create_client_hello()
            self.logger.info("Sending ClientHello to server...")
            self.socket.send(client_hello)
            
            # Receive ServerHello response
            self.logger.info("Waiting for ServerHello from server...")
            server_response = self.socket.recv(4096)
            
            if not server_response:
                self.logger.error("No response from server")
                return False
            
            # Process ServerHello
            handshake_complete = self.tls_handshake.process_server_hello(server_response)
            
            # Enable encryption - use correct keys for send vs receive
            # Client sends with client traffic secret
            client_write_keys = self.tls_handshake.get_handshake_keys(is_server=False)
            # Client receives with server traffic secret
            client_read_keys = self.tls_handshake.get_handshake_read_keys(is_server=False)
            
            # Create separate record managers for send and receive
            self.record_manager_send = TLSRecordManager(is_server=False)
            self.record_manager_recv = TLSRecordManager(is_server=False)
            
            self.record_manager_send.enable_encryption("TLS_AES_256_GCM_SHA384", client_write_keys)
            self.record_manager_recv.enable_encryption("TLS_AES_256_GCM_SHA384", client_read_keys)
            
            self.logger.info("Encryption enabled for handshake")
            
            return True
                
        except Exception as e:
            self.logger.error(f"TLS handshake failed: {e}")
            return False
    
    def _start_message_handling(self):
        # Start thread for receiving messages
        receive_thread = threading.Thread(target=self._receive_messages)
        receive_thread.daemon = True
        receive_thread.start()
        
        # Main thread for sending messages
        self._send_messages()
    
    def _receive_messages(self):
        buffer = b""
        
        try:
            while self.connected:
                data = self.socket.recv(4096)
                if not data:
                    break
                
                buffer += data                
                try:
                    messages, buffer = self.record_manager_recv.receive_data(buffer)
                    
                    for msg_type, msg_data in messages:
                        if msg_type == 'application_data':
                            message_text = msg_data.decode('utf-8', errors='ignore')
                            print(f"\n{message_text}")
                            print("You: ", end="", flush=True)
                except Exception as e:
                    self.logger.debug(f"Record processing: {e}")
                
        except Exception as e:
            if self.connected:
                self.logger.error(f"Error receiving messages: {e}")
        finally:
            self.disconnect()
    
    def _send_messages(self):
        """Send messages to server for relay"""
        try:
            mode_str = "🔐 Hybrid PQ-Safe (X25519+ML-KEM-768)" if self.cipher_suite.lower() == 'hybrid' else "🔒 Classical (X25519)"
            print(f"\nSecure Relay Chat - {mode_str}")
            print("Messages sent will be relayed to other connected clients.\n")
            print("You: ", end="", flush=True)
            
            while self.connected:
                message = input()
                
                if message.lower() == 'quit':
                    break
                
                if not message.strip():
                    print("You: ", end="", flush=True)
                    continue
                
                encrypted_data = self.record_manager_send.send_application_data(message.encode())
                self.socket.send(encrypted_data)
                self.logger.info(f"Sent: {message}")
                
                print("You: ", end="", flush=True)
                
        except Exception as e:
            if self.connected:
                self.logger.error(f"Error sending messages: {e}")
        finally:
            self.disconnect()
    
    def disconnect(self):
        self.connected = False
        if self.socket:
            self.socket.close()
            self.socket = None
        self.logger.info(" Disconnected from server")

def main():
    """Main client entry point"""
    cipher_suite = 'classical'
    if len(sys.argv) > 1:
        if sys.argv[1] == '--cipher-suite':
            cipher_suite = sys.argv[2] if len(sys.argv) > 2 else 'classical'
    
    client = TLSClient(cipher_suite=cipher_suite)
    
    try:
        client.connect()
    except KeyboardInterrupt:
        client.logger.info("Received interrupt signal")
    finally:
        client.disconnect()

if __name__ == "__main__":
    main()