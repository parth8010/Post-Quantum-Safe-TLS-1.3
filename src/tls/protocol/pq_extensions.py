"""
Post-Quantum Extensions for TLS 1.3 Handshake
Supports X25519 + ML-KEM hybrid key exchange
"""

import struct


class PQKeyShareExtension:
    """PQ Key Share Extension for ClientHello/ServerHello"""
    
    EXTENSION_TYPE = 0x3051  # Custom type for PQ key share
    
    def __init__(self):
        self.x25519_key = None
        self.mlkem_key = None
    
    def serialize(self, x25519_key, mlkem_key):
        """Serialize PQ key share extension"""
        data = b''
        
        # X25519 key share (32 bytes)
        data += struct.pack('>H', 32)  # Length
        data += x25519_key
        
        # ML-KEM key share (1184 bytes for ML-KEM-768)
        data += struct.pack('>H', 1184)  # Length
        data += mlkem_key
        
        return data
    
    def deserialize(self, data):
        """Deserialize PQ key share extension"""
        offset = 0
        
        # X25519 key
        x25519_len = struct.unpack('>H', data[offset:offset+2])[0]
        offset += 2
        self.x25519_key = data[offset:offset+x25519_len]
        offset += x25519_len
        
        # ML-KEM key
        mlkem_len = struct.unpack('>H', data[offset:offset+2])[0]
        offset += 2
        self.mlkem_key = data[offset:offset+mlkem_len]
        offset += mlkem_len
        
        return offset


class PQEncapsulationExtension:
    """PQ Encapsulation Extension for ServerHello (ciphertexts)"""
    
    EXTENSION_TYPE = 0x3052  # Custom type for PQ encapsulation
    
    def __init__(self):
        self.mlkem_ciphertext = None
    
    def serialize(self, mlkem_ct):
        """Serialize PQ encapsulation extension"""
        data = b''
        
        # ML-KEM ciphertext (768 bytes for ML-KEM-768)
        data += struct.pack('>H', len(mlkem_ct))
        data += mlkem_ct
        
        return data
    
    def deserialize(self, data):
        """Deserialize PQ encapsulation extension"""
        offset = 0
        
        # ML-KEM ciphertext
        ct_len = struct.unpack('>H', data[offset:offset+2])[0]
        offset += 2
        self.mlkem_ciphertext = data[offset:offset+ct_len]
        offset += ct_len
        
        return offset


class PQCipherSuiteExtension:
    """PQ Cipher Suite Identifier Extension"""
    
    EXTENSION_TYPE = 0x3053
    
    # Cipher suite IDs
    CLASSICAL_ONLY = 0x01  # X25519 only
    HYBRID = 0x02          # X25519 + ML-KEM
    PURE_PQ = 0x03         # ML-KEM only
    
    def __init__(self, cipher_suite_id):
        self.cipher_suite_id = cipher_suite_id
    
    def serialize(self):
        """Serialize cipher suite extension"""
        return struct.pack('>B', self.cipher_suite_id)
    
    def deserialize(self, data):
        """Deserialize cipher suite extension"""
        self.cipher_suite_id = struct.unpack('>B', data[0:1])[0]
        return 1
