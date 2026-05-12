
import logging
import struct
import hashlib
from enum import Enum
from typing import Dict, List, Optional, Tuple

from ..crypto.foundation import (
    generate_ephemeral_key, 
    compute_shared_secret, 
    generate_random_bytes,
    hkdf_extract,
    hkdf_expand_label
)
from ..crypto.key_schedule import TLSKeySchedule
from ..crypto.cipher_suites import CipherSuiteFactory

logger = logging.getLogger("TLSHandshake")

class HandshakeType(Enum):
    CLIENT_HELLO = 1
    SERVER_HELLO = 2
    NEW_SESSION_TICKET = 4
    ENCRYPTED_EXTENSIONS = 8
    CERTIFICATE = 11
    CERTIFICATE_VERIFY = 15
    FINISHED = 20
    KEY_UPDATE = 24

class TLSVersion(Enum):
    TLS_1_2 = 0x0303
    TLS_1_3 = 0x0304

class CipherSuites(Enum):
    TLS_AES_128_GCM_SHA256 = 0x1301
    TLS_AES_256_GCM_SHA384 = 0x1302
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303

class NamedGroups(Enum):
    """Supported groups for key exchange (RFC 8446 B.3.1.4)"""
    x25519 = 0x001D
    x448 = 0x001E
    secp256r1 = 0x0017
    secp384r1 = 0x0018
    secp521r1 = 0x0019

class SignatureSchemes(Enum):
    """Signature algorithms (RFC 8446 B.3.1.3)"""
    rsa_pss_rsae_sha256 = 0x0804
    rsa_pss_rsae_sha384 = 0x0805
    rsa_pss_rsae_sha512 = 0x0806
    ecdsa_secp256r1_sha256 = 0x0403
    ecdsa_secp384r1_sha384 = 0x0503
    ed25519 = 0x0807
    ed448 = 0x0808

class ExtensionType(Enum):
    """Extension types (RFC 8446 B.3.1)"""
    server_name = 0
    supported_groups = 10
    signature_algorithms = 13
    supported_versions = 43
    cookie = 44
    key_share = 51

class HandshakeMessage:
    
    def __init__(self, msg_type: HandshakeType):
        self.msg_type = msg_type
        
    def serialize(self) -> bytes:
        raise NotImplementedError
        
    @classmethod
    def deserialize(cls, data: bytes):
        """Deserialize message from bytes"""
        raise NotImplementedError


class ClientHello(HandshakeMessage):
    """RFC 8446 Section 4.1.2 - ClientHello Message"""
    
    def __init__(self):
        super().__init__(HandshakeType.CLIENT_HELLO)
        # RFC 8446: legacy_version MUST be 0x0303
        self.legacy_version = 0x0303  # TLS 1.2
        self.random = generate_random_bytes(32)
        # RFC 8446: legacy_session_id MUST be empty for TLS 1.3
        self.legacy_session_id = b""
        # Cipher suites the client supports
        self.cipher_suites = [CipherSuites.TLS_AES_256_GCM_SHA384]
        # RFC 8446: legacy_compression_methods MUST be [0] for null compression
        self.legacy_compression_methods = [0]
        # Extensions dictionary
        self.extensions = {}
        
        # Generate key share for ECDHE (X25519)
        self.private_key, self.public_key = generate_ephemeral_key()
        
        # Mandatory extensions
        self._add_supported_versions_extension()
        self._add_key_share_extension()
        self._add_signature_algorithms_extension()
        self._add_supported_groups_extension()
        
        # Store raw bytes for transcript hash
        self._raw_bytes = None
    
    def _add_supported_versions_extension(self):
        """Add supported_versions extension (RFC 8446 4.2.1)
        Advertise TLS 1.3 only"""
        # Format: for ClientHello: ProtocolVersion versions<2..254>
        versions_data = struct.pack('>B', 2)  # Length of versions list
        versions_data += struct.pack('>H', 0x0304)  # TLS 1.3
        self.extensions['supported_versions'] = {
            'type': ExtensionType.supported_versions,
            'data': versions_data
        }
    
    def _add_key_share_extension(self):
        """Add key_share extension (RFC 8446 4.2.8)
        Format: KeyShareEntry client_shares<0..2^16-1>
        KeyShareEntry: NamedGroup group + opaque key_exchange<1..2^16-1>"""
        key_share_data = b''
        # KeyShareEntry for x25519
        group = NamedGroups.x25519.value
        key_share_data += struct.pack('>H', group)  # NamedGroup (2 bytes)
        key_share_data += struct.pack('>H', len(self.public_key))  # key_exchange length
        key_share_data += self.public_key  # key_exchange (32 bytes for x25519)
        
        # Wrap in client_shares vector
        shares_data = struct.pack('>H', len(key_share_data))
        shares_data += key_share_data
        
        self.extensions['key_share'] = {
            'type': ExtensionType.key_share,
            'data': shares_data
        }
    
    def _add_signature_algorithms_extension(self):
        """Add signature_algorithms extension (RFC 8446 4.2.3)
        List supported signature schemes"""
        sig_schemes = [
            SignatureSchemes.ecdsa_secp256r1_sha256,
            SignatureSchemes.rsa_pss_rsae_sha256,
        ]
        sig_data = struct.pack('>H', len(sig_schemes) * 2)
        for scheme in sig_schemes:
            sig_data += struct.pack('>H', scheme.value)
        
        self.extensions['signature_algorithms'] = {
            'type': ExtensionType.signature_algorithms,
            'data': sig_data
        }
    
    def _add_supported_groups_extension(self):
        """Add supported_groups extension (RFC 8446 4.2.7)
        List supported groups for key exchange"""
        groups = [NamedGroups.x25519, NamedGroups.secp256r1]
        groups_data = struct.pack('>H', len(groups) * 2)
        for group in groups:
            groups_data += struct.pack('>H', group.value)
        
        self.extensions['supported_groups'] = {
            'type': ExtensionType.supported_groups,
            'data': groups_data
        }
    
    def serialize(self) -> bytes:
        """RFC 8446 4.1.2 - Serialize ClientHello
        
        ClientHello structure:
        - legacy_version (2 bytes)
        - random (32 bytes)
        - legacy_session_id<0..32>
        - cipher_suites<2..2^16-2>
        - legacy_compression_methods<1..2^8-1>
        - extensions<8..2^16-1>
        """
        # Build message body (without handshake type/length header)
        body = b''
        
        # legacy_version: 0x0303
        body += struct.pack('>H', self.legacy_version)
        
        # random: 32 bytes
        body += self.random
        
        # legacy_session_id: length prefix (1 byte) + data
        body += struct.pack('>B', len(self.legacy_session_id))
        body += self.legacy_session_id
        
        # cipher_suites: length prefix (2 bytes) + suite values
        cipher_data = b''.join(
            struct.pack('>H', cs.value) for cs in self.cipher_suites
        )
        body += struct.pack('>H', len(cipher_data))
        body += cipher_data
        
        # legacy_compression_methods: length prefix (1 byte) + methods
        body += struct.pack('>B', len(self.legacy_compression_methods))
        body += bytes(self.legacy_compression_methods)
        
        # extensions: length prefix (2 bytes) + extension list
        extensions_data = self._serialize_extensions()
        body += struct.pack('>H', len(extensions_data))
        body += extensions_data
        
        # Handshake message format: type (1 byte) + length (3 bytes) + body
        message = struct.pack('>B', self.msg_type.value)
        message += struct.pack('>I', len(body))[1:]  # 3-byte length
        message += body
        
        # Store raw bytes for transcript hash
        self._raw_bytes = message
        
        logger.debug(f"ClientHello serialized: {len(message)} bytes")
        return message
    
    def _serialize_extensions(self) -> bytes:
        """Serialize all extensions to bytes
        Format: Extension struct list
        Extension: type (2 bytes) + data_length (2 bytes) + data"""
        extensions_bytes = b''
        
        # Iterate through extensions in consistent order
        extension_order = [
            'supported_versions',
            'supported_groups',
            'signature_algorithms',
            'key_share'
        ]
        
        for ext_name in extension_order:
            if ext_name in self.extensions:
                ext = self.extensions[ext_name]
                ext_type = ext['type'].value
                ext_data = ext['data']
                
                extensions_bytes += struct.pack('>H', ext_type)  # Extension type
                extensions_bytes += struct.pack('>H', len(ext_data))  # Data length
                extensions_bytes += ext_data  # Extension data
        
        return extensions_bytes
    
    def get_raw_bytes(self) -> bytes:
        """Get raw message bytes (for transcript hash)"""
        if self._raw_bytes is None:
            self.serialize()
        return self._raw_bytes
    
    @classmethod
    def deserialize(cls, data: bytes):
        """Deserialize ClientHello from bytes"""
        hello = cls()
        # TODO: Implement proper parsing
        return hello
    
    @staticmethod
    def extract_key_share_from_bytes(data: bytes) -> bytes:
        """Extract the X25519 public key from ClientHello bytes
        
        ClientHello message format:
        - Handshake type (1 byte)
        - Length (3 bytes)
        - legacy_version (2 bytes)
        - random (32 bytes)
        - session_id length (1 byte) + session_id data
        - cipher_suites length (2 bytes) + cipher_suites data
        - compression_methods length (1 byte) + compression_methods data
        - extensions length (2 bytes) + extensions data
        
        Returns the 32-byte X25519 public key from key_share extension
        """
        try:
            # Skip handshake header (1 + 3 = 4 bytes)
            offset = 4
            
            # Skip legacy_version (2 bytes) + random (32 bytes)
            offset += 2 + 32
            
            # Skip session_id (length byte + data)
            session_id_len = data[offset]
            offset += 1 + session_id_len
            
            # Skip cipher_suites (length 2 bytes + data)
            cipher_len = struct.unpack('>H', data[offset:offset+2])[0]
            offset += 2 + cipher_len
            
            # Skip compression_methods (length 1 byte + data)
            compression_len = data[offset]
            offset += 1 + compression_len
            
            # Parse extensions (length 2 bytes + extensions data)
            extensions_len = struct.unpack('>H', data[offset:offset+2])[0]
            offset += 2
            extensions_end = offset + extensions_len
            
            # Parse extensions to find key_share
            while offset < extensions_end:
                ext_type = struct.unpack('>H', data[offset:offset+2])[0]
                offset += 2
                ext_len = struct.unpack('>H', data[offset:offset+2])[0]
                offset += 2
                ext_data = data[offset:offset+ext_len]
                offset += ext_len
                
                # Check if this is the key_share extension (type 51)
                if ext_type == 51:
                    # key_share extension format:
                    # - For ClientHello: client_shares<0..2^16-1>
                    # - client_shares contains KeyShareEntry list
                    # - KeyShareEntry: group (2 bytes) + key_exchange<1..2^16-1>
                    
                    # First 2 bytes are the length of shares
                    shares_len = struct.unpack('>H', ext_data[0:2])[0]
                    shares_offset = 2
                    
                    # Read first KeyShareEntry
                    # group (2 bytes)
                    shares_offset += 2
                    # key_exchange length (2 bytes) + key_exchange
                    key_len = struct.unpack('>H', ext_data[shares_offset:shares_offset+2])[0]
                    shares_offset += 2
                    public_key = ext_data[shares_offset:shares_offset+key_len]
                    
                    return public_key
            
            logger.warning("key_share extension not found in ClientHello")
            return None
            
        except Exception as e:
            logger.error(f"Failed to extract key_share from ClientHello: {e}")
            return None


class ServerHello(HandshakeMessage):
    """RFC 8446 Section 4.1.3 - ServerHello Message"""
    
    def __init__(self):
        super().__init__(HandshakeType.SERVER_HELLO)
        # RFC 8446: legacy_version MUST be 0x0303
        self.legacy_version = 0x0303  # TLS 1.2
        self.random = generate_random_bytes(32)
        # RFC 8446: legacy_session_id_echo echoes client's session_id
        self.legacy_session_id_echo = b""
        # Selected cipher suite
        self.cipher_suite = CipherSuites.TLS_AES_256_GCM_SHA384
        # RFC 8446: legacy_compression_method MUST be 0
        self.legacy_compression_method = 0
        # Extensions dictionary
        self.extensions = {}
        
        # Generate key share for ECDHE (X25519)
        self.private_key, self.public_key = generate_ephemeral_key()
        
        # Mandatory extensions
        self._add_supported_versions_extension()
        self._add_key_share_extension()
        
        # Store raw bytes for transcript hash
        self._raw_bytes = None
    
    def _add_supported_versions_extension(self):
        """Add supported_versions extension (RFC 8446 4.2.1)
        For ServerHello: ProtocolVersion selected_version"""
        versions_data = struct.pack('>H', 0x0304)  # TLS 1.3
        self.extensions['supported_versions'] = {
            'type': ExtensionType.supported_versions,
            'data': versions_data
        }
    
    def _add_key_share_extension(self):
        """Add key_share extension (RFC 8446 4.2.8)
        For ServerHello: KeyShareEntry server_share"""
        key_share_data = b''
        # KeyShareEntry for x25519
        group = NamedGroups.x25519.value
        key_share_data += struct.pack('>H', group)  # NamedGroup
        key_share_data += struct.pack('>H', len(self.public_key))  # key_exchange length
        key_share_data += self.public_key  # key_exchange (32 bytes for x25519)
        
        self.extensions['key_share'] = {
            'type': ExtensionType.key_share,
            'data': key_share_data
        }
    
    def serialize(self) -> bytes:
        """RFC 8446 4.1.3 - Serialize ServerHello
        
        ServerHello structure:
        - legacy_version (2 bytes)
        - random (32 bytes)
        - legacy_session_id_echo<0..32>
        - cipher_suite (2 bytes)
        - legacy_compression_method (1 byte)
        - extensions<6..2^16-1>
        """
        # Build message body
        body = b''
        
        # legacy_version: 0x0303
        body += struct.pack('>H', self.legacy_version)
        
        # random: 32 bytes
        body += self.random
        
        # legacy_session_id_echo: length prefix (1 byte) + data
        body += struct.pack('>B', len(self.legacy_session_id_echo))
        body += self.legacy_session_id_echo
        
        # cipher_suite: 2 bytes
        body += struct.pack('>H', self.cipher_suite.value)
        
        # legacy_compression_method: 1 byte (must be 0)
        body += struct.pack('>B', self.legacy_compression_method)
        
        # extensions: length prefix (2 bytes) + extension list
        extensions_data = self._serialize_extensions()
        body += struct.pack('>H', len(extensions_data))
        body += extensions_data
        
        # Handshake message format: type (1 byte) + length (3 bytes) + body
        message = struct.pack('>B', self.msg_type.value)
        message += struct.pack('>I', len(body))[1:]  # 3-byte length
        message += body
        
        # Store raw bytes for transcript hash
        self._raw_bytes = message
        
        logger.debug(f"ServerHello serialized: {len(message)} bytes")
        return message
    
    def _serialize_extensions(self) -> bytes:
        """Serialize all extensions to bytes"""
        extensions_bytes = b''
        
        # Extensions in order
        extension_order = [
            'supported_versions',
            'key_share'
        ]
        
        for ext_name in extension_order:
            if ext_name in self.extensions:
                ext = self.extensions[ext_name]
                ext_type = ext['type'].value
                ext_data = ext['data']
                
                extensions_bytes += struct.pack('>H', ext_type)
                extensions_bytes += struct.pack('>H', len(ext_data))
                extensions_bytes += ext_data
        
        return extensions_bytes
    
    def get_raw_bytes(self) -> bytes:
        """Get raw message bytes (for transcript hash)"""
        if self._raw_bytes is None:
            self.serialize()
        return self._raw_bytes
    
    @classmethod
    def deserialize(cls, data: bytes):
        """Deserialize ServerHello from bytes"""
        hello = cls()
        # TODO: Implement proper parsing
        return hello
    
    @staticmethod
    def extract_key_share_from_bytes(data: bytes) -> bytes:
        """Extract the X25519 public key from ServerHello bytes
        
        ServerHello message format:
        - Handshake type (1 byte)
        - Length (3 bytes)
        - legacy_version (2 bytes)
        - random (32 bytes)
        - session_id_echo length (1 byte) + session_id_echo data
        - cipher_suite (2 bytes)
        - legacy_compression_method (1 byte)
        - extensions length (2 bytes) + extensions data
        
        Returns the 32-byte X25519 public key from key_share extension
        """
        try:
            # Skip handshake header (1 + 3 = 4 bytes)
            offset = 4
            
            # Skip legacy_version (2 bytes) + random (32 bytes)
            offset += 2 + 32
            
            # Skip session_id_echo (length byte + data)
            session_id_len = data[offset]
            offset += 1 + session_id_len
            
            # Skip cipher_suite (2 bytes) + legacy_compression_method (1 byte)
            offset += 2 + 1
            
            # Parse extensions (length 2 bytes + extensions data)
            extensions_len = struct.unpack('>H', data[offset:offset+2])[0]
            offset += 2
            extensions_end = offset + extensions_len
            
            # Parse extensions to find key_share
            while offset < extensions_end:
                ext_type = struct.unpack('>H', data[offset:offset+2])[0]
                offset += 2
                ext_len = struct.unpack('>H', data[offset:offset+2])[0]
                offset += 2
                ext_data = data[offset:offset+ext_len]
                offset += ext_len
                
                # Check if this is the key_share extension (type 51)
                if ext_type == 51:
                    # key_share extension format for ServerHello:
                    # - KeyShareEntry server_share
                    # - KeyShareEntry: group (2 bytes) + key_exchange<1..2^16-1>
                    
                    # Read KeyShareEntry
                    # group (2 bytes)
                    share_offset = 2
                    # key_exchange length (2 bytes) + key_exchange
                    key_len = struct.unpack('>H', ext_data[share_offset:share_offset+2])[0]
                    share_offset += 2
                    public_key = ext_data[share_offset:share_offset+key_len]
                    
                    return public_key
            
            logger.warning("key_share extension not found in ServerHello")
            return None
            
        except Exception as e:
            logger.error(f"Failed to extract key_share from ServerHello: {e}")
            return None


class EncryptedExtensions(HandshakeMessage):
    """RFC 8446 Section 4.3.1 - EncryptedExtensions Message"""
    
    def __init__(self):
        super().__init__(HandshakeType.ENCRYPTED_EXTENSIONS)
        self.extensions = {}
        self._raw_bytes = None
    
    def serialize(self) -> bytes:
        """Serialize EncryptedExtensions
        
        EncryptedExtensions:
        - extensions<0..2^16-1>
        """
        body = b''
        
        # Extensions (can be empty for now)
        extensions_data = b''  # No extensions required for basic TLS 1.3
        body += struct.pack('>H', len(extensions_data))
        body += extensions_data
        
        # Handshake message format
        message = struct.pack('>B', self.msg_type.value)
        message += struct.pack('>I', len(body))[1:]  # 3-byte length
        message += body
        
        self._raw_bytes = message
        logger.debug(f"EncryptedExtensions serialized: {len(message)} bytes")
        return message
    
    def get_raw_bytes(self) -> bytes:
        if self._raw_bytes is None:
            self.serialize()
        return self._raw_bytes


class Certificate(HandshakeMessage):
    """RFC 8446 Section 4.4.2 - Certificate Message"""
    
    def __init__(self, cert_chain: List[bytes] = None):
        super().__init__(HandshakeType.CERTIFICATE)
        # List of certificate entries
        self.cert_list = cert_chain if cert_chain else []
        self._raw_bytes = None
    
    def serialize(self) -> bytes:
        """Serialize Certificate message
        
        Certificate:
        - certificate_request_context<0..2^8-1>
        - CertificateEntry cert_list<0..2^24-1>
        
        CertificateEntry:
        - opaque cert_data<1..2^24-1>
        - Extension extensions<0..2^16-1>
        """
        body = b''
        
        # certificate_request_context: empty for server
        body += struct.pack('>B', 0)  # context length (0)
        
        # Build certificate list
        cert_list_data = b''
        for cert_bytes in self.cert_list:
            # cert_data with 3-byte length prefix
            cert_list_data += struct.pack('>I', len(cert_bytes))[1:]
            cert_list_data += cert_bytes
            # extensions (empty for now)
            cert_list_data += struct.pack('>H', 0)
        
        # cert_list with 3-byte length prefix
        body += struct.pack('>I', len(cert_list_data))[1:]
        body += cert_list_data
        
        # Handshake message format
        message = struct.pack('>B', self.msg_type.value)
        message += struct.pack('>I', len(body))[1:]  # 3-byte length
        message += body
        
        self._raw_bytes = message
        logger.debug(f"Certificate serialized: {len(message)} bytes")
        return message
    
    def get_raw_bytes(self) -> bytes:
        if self._raw_bytes is None:
            self.serialize()
        return self._raw_bytes


class CertificateVerify(HandshakeMessage):
    """RFC 8446 Section 4.4.3 - CertificateVerify Message"""
    
    def __init__(self, signature: bytes = None):
        super().__init__(HandshakeType.CERTIFICATE_VERIFY)
        self.algorithm = SignatureSchemes.ecdsa_secp256r1_sha256
        self.signature = signature if signature else b''
        self._raw_bytes = None
    
    def serialize(self) -> bytes:
        """Serialize CertificateVerify message
        
        CertificateVerify:
        - SignatureScheme algorithm
        - opaque signature<0..2^16-1>
        """
        body = b''
        
        # algorithm (2 bytes)
        body += struct.pack('>H', self.algorithm.value)
        
        # signature with 2-byte length prefix
        body += struct.pack('>H', len(self.signature))
        body += self.signature
        
        # Handshake message format
        message = struct.pack('>B', self.msg_type.value)
        message += struct.pack('>I', len(body))[1:]  # 3-byte length
        message += body
        
        self._raw_bytes = message
        logger.debug(f"CertificateVerify serialized: {len(message)} bytes")
        return message
    
    def get_raw_bytes(self) -> bytes:
        if self._raw_bytes is None:
            self.serialize()
        return self._raw_bytes


class Finished(HandshakeMessage):
    """RFC 8446 Section 4.4.4 - Finished Message"""
    
    def __init__(self, verify_data: bytes = None):
        super().__init__(HandshakeType.FINISHED)
        # verify_data is HMAC-based (32 bytes for SHA-256, 48 for SHA-384)
        self.verify_data = verify_data if verify_data else b''
        self._raw_bytes = None
        
    def serialize(self) -> bytes:
        """Serialize Finished message
        
        Finished:
        - opaque verify_data[Hash.length]
        """
        body = self.verify_data
        
        # Handshake message format
        message = struct.pack('>B', self.msg_type.value)
        message += struct.pack('>I', len(body))[1:]  # 3-byte length
        message += body
        
        self._raw_bytes = message
        logger.debug(f"Finished serialized: {len(message)} bytes")
        return message
    
    def get_raw_bytes(self) -> bytes:
        if self._raw_bytes is None:
            self.serialize()
        return self._raw_bytes


class TLSHandshake:
    """Main TLS handshake state machine (RFC 8446 Appendix A)"""
    
    def __init__(self, is_server: bool = False):
        self.is_server = is_server
        self.state = "INIT"
        self.key_schedule = TLSKeySchedule()
        self.client_hello = None
        self.server_hello = None
        self.shared_secret = None
        
        # Transcript for computing handshake context (RFC 8446 4.4.1)
        self.transcript = b""  # Concatenation of all handshake messages
        self.hash_function = hashlib.sha384  # For TLS_AES_256_GCM_SHA384
        
    def add_to_transcript(self, handshake_message: HandshakeMessage):
        """Add a handshake message to the transcript (RFC 8446 4.4.1)
        Includes handshake type and length fields but NOT record layer headers"""
        if hasattr(handshake_message, 'get_raw_bytes'):
            self.transcript += handshake_message.get_raw_bytes()
        elif hasattr(handshake_message, '_raw_bytes') and handshake_message._raw_bytes:
            self.transcript += handshake_message._raw_bytes
        logger.debug(f"Added to transcript. Current length: {len(self.transcript)} bytes")
    
    def compute_transcript_hash(self) -> bytes:
        """Compute Transcript-Hash(M1, M2, ... Mn)
        RFC 8446 4.4.1: Hash(M1 || M2 || ... || Mn)"""
        return self.hash_function(self.transcript).digest()
    
    def process_client_hello(self, data: bytes) -> Tuple[Optional[bytes], bool]:
        """Server-side: Process ClientHello and respond with ServerHello"""
        if not self.is_server:
            raise RuntimeError("ClientHello processing only on server side")
            
        logger.info("Processing ClientHello...")
        
        # Create a ClientHello object for transcript
        self.client_hello = ClientHello()
        self.client_hello._raw_bytes = data  # Use provided data as raw bytes
        
        # Extract client's actual public key from the received ClientHello bytes
        client_public_key = ClientHello.extract_key_share_from_bytes(data)
        if client_public_key:
            self.client_hello.public_key = client_public_key
            logger.debug(f"Extracted client public key: {len(client_public_key)} bytes")
        else:
            logger.error("Failed to extract client public key from ClientHello")
            return None, False
        
        # Add to transcript
        self.add_to_transcript(self.client_hello)
        
        # Create ServerHello response
        self.server_hello = ServerHello()
        
        # Compute shared secret from key shares
        # Server's private key (self.server_hello.private_key) XOR client's public key (extracted from ClientHello)
        self.shared_secret = compute_shared_secret(
            self.server_hello.private_key,
            client_public_key
        )
        logger.debug(f"Computed shared secret: {len(self.shared_secret)} bytes")
        
        # Serialize ServerHello and add to transcript BEFORE deriving secrets
        server_hello_bytes = self.server_hello.serialize()
        self.add_to_transcript(self.server_hello)
        
        # Derive handshake secrets using key schedule (with ClientHello + ServerHello in transcript)
        self._derive_handshake_secrets()
        
        logger.info("ClientHello processed, ServerHello ready")
        self.state = "SERVER_HELLO_SENT"
        
        # Return ServerHello message
        return server_hello_bytes, False
    
    def process_server_hello(self, data: bytes) -> bool:
        """Client-side: Process ServerHello"""
        if self.is_server:
            raise RuntimeError("ServerHello processing only on client side")
            
        logger.info("Processing ServerHello...")
        
        # Create a ServerHello object for transcript
        self.server_hello = ServerHello()
        self.server_hello._raw_bytes = data
        
        # Extract server's actual public key from the received ServerHello bytes
        server_public_key = ServerHello.extract_key_share_from_bytes(data)
        if server_public_key:
            self.server_hello.public_key = server_public_key
            logger.debug(f"Extracted server public key: {len(server_public_key)} bytes")
        else:
            logger.error("Failed to extract server public key from ServerHello")
            return False
        
        # Add to transcript
        self.add_to_transcript(self.server_hello)
        
        # Compute shared secret from key shares
        # Client's private key (self.client_hello.private_key) XOR server's public key (extracted from ServerHello)
        self.shared_secret = compute_shared_secret(
            self.client_hello.private_key,
            server_public_key
        )
        logger.debug(f"Computed shared secret: {len(self.shared_secret)} bytes")
        
        # Derive handshake secrets
        self._derive_handshake_secrets()
        
        logger.info("ServerHello processed, handshake secrets derived")
        self.state = "HANDSHAKE_KEYS_DERIVED"
        
        return True
    
    def _derive_handshake_secrets(self):
        """Derive handshake traffic secrets using key schedule (RFC 8446 7.1)"""
        if self.shared_secret is None:
            raise RuntimeError("Shared secret not computed")
        
        # Step 1: Derive handshake secret (early secret + shared secret)
        self.key_schedule.derive_handshake_secrets(
            self.shared_secret,
            self.client_hello.random if self.client_hello else b'',
            self.server_hello.random if self.server_hello else b''
        )
        
        # Step 2: Compute handshake context (transcript hash up to ServerHello)
        handshake_context = self.compute_transcript_hash()
        
        # Step 3: Derive handshake traffic secrets using transcript hash
        self.key_schedule.derive_handshake_traffic_secrets(handshake_context)
        
        logger.debug("Handshake secrets and traffic secrets derived")
    
    def create_client_hello(self) -> bytes:
        """Client-side: Create and send ClientHello"""
        if self.is_server:
            raise RuntimeError("ClientHello creation only on client side")
            
        logger.info("Creating ClientHello...")
        self.client_hello = ClientHello()
        hello_bytes = self.client_hello.serialize()
        self.add_to_transcript(self.client_hello)
        self.state = "CLIENT_HELLO_SENT"
        return hello_bytes
    
    def create_finished(self, is_server: bool) -> bytes:
        """Create Finished message (RFC 8446 4.4.4)
        verify_data = HMAC(finished_key, transcript_hash)"""
        
        # Get finished key from key schedule
        if is_server:
            finished_key = self.key_schedule.get_server_finished_key()
        else:
            finished_key = self.key_schedule.get_client_finished_key()
        
        # Compute transcript hash
        transcript_hash = self.compute_transcript_hash()
        
        # Compute verify_data = HMAC(finished_key, transcript_hash)
        h = hashlib.sha256()
        if hasattr(hashlib, 'new'):
            import hmac as hmac_module
            verify_data = hmac_module.new(finished_key, transcript_hash, hashlib.sha256).digest()
        else:
            verify_data = b''
        
        # Create Finished message
        finished = Finished(verify_data)
        finished_bytes = finished.serialize()
        self.add_to_transcript(finished)
        
        logger.info(f"Finished message created: {len(finished_bytes)} bytes")
        return finished_bytes
    
    def get_handshake_keys(self, is_server: bool) -> Dict:
        """Get encryption keys for handshake phase (for writing/sending)"""
        if is_server:
            return self.key_schedule.get_server_handshake_keys()
        else:
            return self.key_schedule.get_client_handshake_keys()
    
    def get_handshake_read_keys(self, is_server: bool) -> Dict:
        """Get encryption keys for reading peer messages during handshake
        
        - If is_server=True: read CLIENT messages (use client traffic secret)
        - If is_server=False: read SERVER messages (use server traffic secret)
        """
        if is_server:
            # Server reads from client
            return self.key_schedule.derive_traffic_keys(
                self.key_schedule.client_handshake_traffic_secret
            )
        else:
            # Client reads from server
            return self.key_schedule.derive_traffic_keys(
                self.key_schedule.server_handshake_traffic_secret
            )
    
    def get_application_keys(self, is_server: bool) -> Dict:
        """Get encryption keys for application phase (for writing/sending)"""
        if is_server:
            return self.key_schedule.get_server_application_keys()
        else:
            return self.key_schedule.get_client_application_keys()
    
    def get_application_read_keys(self, is_server: bool) -> Dict:
        """Get encryption keys for reading peer messages during application phase
        
        - If is_server=True: read CLIENT messages (use client traffic secret)
        - If is_server=False: read SERVER messages (use server traffic secret)
        """
        if is_server:
            # Server reads from client
            return self.key_schedule.derive_traffic_keys(
                self.key_schedule.client_application_traffic_secret
            )
        else:
            # Client reads from server
            return self.key_schedule.derive_traffic_keys(
                self.key_schedule.server_application_traffic_secret
            )