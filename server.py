
import socket
import threading
import logging
from src.config import ServerConfig
from src.utils.logging import setup_logging
from src.tls.protocol.handshake import TLSHandshake, ClientHello
from src.tls.protocol.hybrid_handshake import HybridTLSHandshake
from src.tls.protocol.record_layer import TLSRecordManager

class TLSServer:
    def __init__(self, host='localhost', port=8443, cipher_suite='classical'):
        self.host = host
        self.port = port
        self.cipher_suite = cipher_suite  # 'classical' or 'hybrid'
        self.running = False
        self.clients = {}  # client_id -> client_info
        
        # Setup logging
        setup_logging()
        self.logger = logging.getLogger("TLSServer")
        
        # Load configuration
        self.config = ServerConfig()
        self.logger.info(f"Using cipher suite: {cipher_suite.upper()}")
        
    def start(self):
        """Start the TLS messaging server"""
        try:
            # Create TCP socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Bind and listen
            self.socket.bind((self.host, self.port))
            self.socket.listen(5)
            self.socket.settimeout(1.0)  # Non-blocking with timeout
            
            self.running = True
            mode_str = "🔐 Hybrid PQ-Safe (X25519+ML-KEM-768)" if self.cipher_suite.lower() == 'hybrid' else "🔒 Classical (X25519)"
            self.logger.info(f"TLS Server started on {self.host}:{self.port} - {mode_str}")
            self.logger.info("Waiting for incoming connections...")            
            self._accept_connections()
            
        except Exception as e:
            self.logger.error(f"Failed to start server: {e}")
            self.stop()
    
    def _accept_connections(self):
        """Accept incoming client connections"""
        while self.running:
            try:
                client_socket, client_address = self.socket.accept()
                self.logger.info(f"New connection from {client_address}")                
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_socket, client_address)
                )
                client_thread.daemon = True
                client_thread.start()
                
            except socket.timeout:
                # Timeout is normal - just check if we should keep running
                continue
            except Exception as e:
                if self.running:
                    self.logger.error(f"Error accepting connection: {e}")
    
    def _handle_client(self, client_socket, client_address):
        """Handle individual client connection with TLS 1.3"""
        client_id = f"{client_address[0]}:{client_address[1]}"
        
        try:
            # Initialize TLS for this connection
            if self.cipher_suite.lower() == 'hybrid':
                tls_handshake = HybridTLSHandshake(is_server=True)
                self.logger.info(f" Hybrid PQ-Safe handshake with {client_id}")
            else:
                tls_handshake = TLSHandshake(is_server=True)
            record_manager = TLSRecordManager(is_server=True)  # Placeholder
            
            self.logger.info(f" Starting TLS 1.3 handshake with {client_id}")
            
            # Perform TLS handshake
            handshake_result = self._perform_tls_handshake(client_socket, client_id, tls_handshake, record_manager)
            
            if isinstance(handshake_result, tuple):
                success, record_manager_send, record_manager_recv = handshake_result
            else:
                success = handshake_result
                record_manager_send = None
                record_manager_recv = None
            
            if success and record_manager_send and record_manager_recv:
                # Store client information
                self.clients[client_id] = {
                    'socket': client_socket,
                    'address': client_address,
                    'tls_handshake': tls_handshake,
                    'record_manager_send': record_manager_send,
                    'record_manager_recv': record_manager_recv,
                    'username': None
                }
                
                # Start secure messaging
                self._handle_secure_messages(client_id)
            else:
                self.logger.warning(f" TLS handshake failed for {client_id}")
                client_socket.close()
                
        except Exception as e:
            self.logger.error(f"Error handling client {client_id}: {e}")
            if client_id in self.clients:
                del self.clients[client_id]
            client_socket.close()
    
    def _perform_tls_handshake(self, client_socket, client_id, tls_handshake, record_manager):
        try:
            # Receive ClientHello
            self.logger.info(f" Waiting for ClientHello from {client_id}")
            client_hello_data = client_socket.recv(4096)
            
            if not client_hello_data:
                self.logger.warning(f"No data received from {client_id}")
                return False, None, None            
            server_hello_data, handshake_complete = tls_handshake.process_client_hello(client_hello_data)
            
            if not server_hello_data:
                self.logger.error(f"Failed to process ClientHello from {client_id}")
                return False, None, None
            
            # Send ServerHello back to client
            self.logger.info(f" Sending ServerHello to {client_id}")
            client_socket.send(server_hello_data)
            
            # Enable encryption with correct keys for send vs receive
            # Server sends with server traffic secret
            server_write_keys = tls_handshake.get_handshake_keys(is_server=True)
            # Server receives with client traffic secret
            server_read_keys = tls_handshake.get_handshake_read_keys(is_server=True)
            
            # Create separate record managers for send and receive
            record_manager_send = TLSRecordManager(is_server=True)
            record_manager_recv = TLSRecordManager(is_server=True)
            
            record_manager_send.enable_encryption("TLS_AES_256_GCM_SHA384", server_write_keys)
            record_manager_recv.enable_encryption("TLS_AES_256_GCM_SHA384", server_read_keys)
            
            self.logger.info(f" TLS handshake completed successfully with {client_id}")
            return True, record_manager_send, record_manager_recv
            
        except Exception as e:
            self.logger.error(f"TLS handshake failed for {client_id}: {e}")
            return False, None, None
    
    def _handle_secure_messages(self, client_id):
        """Handle encrypted messages from client and relay to other clients"""
        client_info = self.clients[client_id]
        client_socket = client_info['socket']
        record_manager_recv = client_info['record_manager_recv']
        record_manager_send = client_info['record_manager_send']
        
        try:
            buffer = b""
            
            while self.running and client_id in self.clients:
                data = client_socket.recv(4096)
                if not data:
                    break
                
                buffer += data                
                messages, buffer = record_manager_recv.receive_data(buffer)
                
                for msg_type, msg_data in messages:
                    if msg_type == 'application_data':
                        # Relay message to all OTHER clients
                        message_text = msg_data.decode('utf-8', errors='ignore')
                        self.logger.info(f"Relay from {client_id}: {message_text}")
                        
                        # Broadcast to all OTHER clients
                        for other_id, other_info in list(self.clients.items()):
                            if other_id != client_id:
                                try:
                                    relay_msg = f"[{client_id}]: {message_text}".encode('utf-8')
                                    encrypted = other_info['record_manager_send'].send_application_data(relay_msg)
                                    other_info['socket'].send(encrypted)
                                except Exception as e:
                                    self.logger.error(f"Failed to relay to {other_id}: {e}")
                
        except Exception as e:
            self.logger.error(f"Error handling secure messages for {client_id}: {e}")
        finally:
            self._disconnect_client(client_id)
    
    def _disconnect_client(self, client_id):
        if client_id in self.clients:
            client_info = self.clients[client_id]
            client_info['socket'].close()
            del self.clients[client_id]
            self.logger.info(f" Client {client_id} disconnected")
    
    def stop(self):
        self.running = False
        self.logger.info(" Shutting down server...")
        
        # Close all client connections
        for client_id in list(self.clients.keys()):
            self._disconnect_client(client_id)
        
        # Close server socket
        if hasattr(self, 'socket'):
            self.socket.close()
        
        self.logger.info(" Server stopped")

def main():
    """Main server entry point"""
    import sys
    
    cipher_suite = 'classical'
    if len(sys.argv) > 1:
        if sys.argv[1] == '--cipher-suite':
            cipher_suite = sys.argv[2] if len(sys.argv) > 2 else 'classical'
    
    server = TLSServer(cipher_suite=cipher_suite)
    
    try:
        server.start()
    except KeyboardInterrupt:
        server.logger.info("Received interrupt signal")
    finally:
        server.stop()

if __name__ == "__main__":
    main()