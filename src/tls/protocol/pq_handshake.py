"""
Post-Quantum TLS Handshake Integration
Extends RFC 8446 TLS 1.3 with hybrid X25519 + ML-KEM key exchange
"""

from src.tls.protocol.handshake import TLSHandshake, ClientHello, ServerHello
from src.tls.crypto.pq_algorithms import HybridKeyExchange, HybridSecretCombination
from src.tls.protocol.pq_extensions import PQKeyShareExtension, PQEncapsulationExtension, PQCipherSuiteExtension
import struct


class PQTLSHandshake:
    """TLS 1.3 Handshake with Post-Quantum Support"""
    
    # Combination methods
    COMBINATION_XOR = "xor"
    COMBINATION_HKDF = "hkdf"
    COMBINATION_CONCAT = "concat"
    COMBINATION_WEIGHTED = "weighted"
    
    def __init__(self, is_server=False, cipher_suite_mode="CLASSICAL"):
        """
        Args:
            is_server: True for server, False for client
            cipher_suite_mode: "CLASSICAL", "HYBRID", or "PURE_PQ"
        """
        self.is_server = is_server
        self.cipher_suite_mode = cipher_suite_mode
        self.combination_method = self.COMBINATION_HKDF  # Default
        
        # Classical TLS handshake
        self.classical_handshake = TLSHandshake(is_server=is_server)
        
        # PQ key exchange
        self.hybrid_kex = HybridKeyExchange() if cipher_suite_mode in ["HYBRID", "PURE_PQ"] else None
        self.hybrid_public_keys = None
        self.hybrid_peer_public_keys = None
        self.hybrid_secrets = None
        
        # Final shared secret
        self.final_shared_secret = None
    
    def process_client_hello_pq(self, data):
        """Process ClientHello with PQ support"""
        # First parse classical handshake
        server_hello_data, _ = self.classical_handshake.process_client_hello(data)
        
        # Extract PQ public keys from ClientHello if present
        client_hello = ClientHello.deserialize(data)
        
        if self.cipher_suite_mode in ["HYBRID", "PURE_PQ"]:
            # Generate server's hybrid keys
            self.hybrid_public_keys = self.hybrid_kex.generate_keypair()
            
            # Extract client's PQ public keys
            pq_ext = PQKeyShareExtension()
            # In real implementation, extract from client_hello extensions
            # For now, we'll add them after
        
        return server_hello_data
    
    def process_server_hello_pq(self, data):
        """Process ServerHello with PQ support"""
        # First parse classical handshake
        self.classical_handshake.process_server_hello(data)
        
        # Extract PQ data
        server_hello = ServerHello.deserialize(data)
        
        if self.cipher_suite_mode in ["HYBRID", "PURE_PQ"]:
            # Encapsulate with server's PQ public keys
            # Extract from server_hello extensions
            pass
    
    def derive_hybrid_secret(self, combination_method=None):
        """Derive final shared secret from hybrid key exchange"""
        if combination_method:
            self.combination_method = combination_method
        
        if not self.hybrid_secrets:
            return None
        
        x25519_ss = self.hybrid_secrets.get('x25519_ss')
        mlkem_ss = self.hybrid_secrets.get('mlkem_ss')
        
        if self.combination_method == self.COMBINATION_XOR:
            return HybridSecretCombination.combine_xor(x25519_ss, mlkem_ss)
        elif self.combination_method == self.COMBINATION_HKDF:
            return HybridSecretCombination.combine_hkdf(x25519_ss, mlkem_ss)
        elif self.combination_method == self.COMBINATION_CONCAT:
            return HybridSecretCombination.combine_concat_hash(x25519_ss, mlkem_ss)
        elif self.combination_method == self.COMBINATION_WEIGHTED:
            return HybridSecretCombination.combine_weighted_xor(x25519_ss, mlkem_ss)
        
        return x25519_ss  # Fallback


class PQKeySchedule:
    """Key schedule with hybrid secret support"""
    
    def __init__(self, hybrid_handshake):
        self.hybrid_handshake = hybrid_handshake
        self.classical_schedule = hybrid_handshake.classical_handshake.key_schedule
    
    def derive_with_hybrid_secret(self, combination_method="hkdf"):
        """Derive keys using combined hybrid secret"""
        hybrid_secret = self.hybrid_handshake.derive_hybrid_secret(combination_method)
        
        if hybrid_secret:
            # Use hybrid secret in key schedule
            return self.classical_schedule.derive_traffic_keys(hybrid_secret[:32])
        
        return self.classical_schedule.derive_traffic_keys(
            self.classical_schedule.server_handshake_traffic_secret
        )
