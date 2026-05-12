
import os
import sys

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("Warning: cryptography library not installed. Run: pip install cryptography")


# Global hash algorithm for TLS 1.3 (TLS_AES_256_GCM_SHA384)
_HASH_ALGORITHM = hashes.SHA384
_HASH_LENGTH = 48  # SHA-384 digest size


def set_hash_algorithm(algorithm: str):
    """Set the hash algorithm for HKDF and key derivation
    
    Args:
        algorithm: "SHA256" or "SHA384"
    """
    global _HASH_ALGORITHM, _HASH_LENGTH
    if algorithm == "SHA256":
        _HASH_ALGORITHM = hashes.SHA256
        _HASH_LENGTH = 32
    elif algorithm == "SHA384":
        _HASH_ALGORITHM = hashes.SHA384
        _HASH_LENGTH = 48
    else:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")


def generate_ephemeral_key():
    """Generates ephemeral key pair for ECDHE key exchange (X25519)"""
    if not CRYPTO_AVAILABLE:
        raise ImportError("cryptography library required. Install with: pip install cryptography")
    
    # Generate X25519 private key
    private_key = x25519.X25519PrivateKey.generate()
    
    # Get public key and serialize to bytes
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    
    return private_key, public_key_bytes


def generate_random_bytes(length=32):
    """Generate cryptographically secure random bytes"""
    return os.urandom(length)


def compute_shared_secret(private_key, peer_public_key_bytes):
    """Compute ECDHE shared secret using X25519"""
    if not CRYPTO_AVAILABLE:
        raise ImportError("cryptography library required")
    
    # Reconstruct peer's public key from bytes
    peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_key_bytes)
    
    # Compute shared secret
    shared_secret = private_key.exchange(peer_public_key)
    return shared_secret


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """RFC 5869 HKDF-Extract
    
    PRK = HMAC-Hash(salt, IKM)
    """
    if not CRYPTO_AVAILABLE:
        raise ImportError("cryptography library required")
    
    # If no salt, use zeros of hash length
    if salt is None:
        salt = b'\x00' * _HASH_LENGTH
    
    # HKDF-Extract: PRK = HMAC-Hash(salt, IKM)
    hash_obj = hashes.Hash(_HASH_ALGORITHM())
    hash_obj.update(salt)
    hash_obj.update(ikm)
    return hash_obj.finalize()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF-Expand
    
    OKM = HKDF-Expand(PRK, info, length)
    """
    if not CRYPTO_AVAILABLE:
        raise ImportError("cryptography library required")
    
    hkdf = HKDF(
        algorithm=_HASH_ALGORITHM(),
        length=length,
        salt=None,
        info=info,
        backend=default_backend()
    )
    return hkdf.derive(prk)


def hkdf_expand_label(secret: bytes, label: str, context: bytes, length: int) -> bytes:
    """RFC 8446 HKDF-Expand-Label
    
    Expand-Label(Secret, Label, Context, Length) =
        HKDF-Expand(Secret, HkdfLabel, Length)
    
    Where HkdfLabel is:
    struct {
        uint16 length = Length;
        opaque label<7..255> = "tls13 " + Label;
        opaque context<0..255> = Context;
    } HkdfLabel;
    """
    # TLS 1.3 HKDF label format (RFC 8446 7.1)
    hkdf_label = (
        length.to_bytes(2, byteorder='big') +  # Length (2 bytes)
        bytes([len(b'tls13 ' + label.encode())]) +  # Label length (1 byte)
        b'tls13 ' + label.encode() +  # Label with "tls13 " prefix
        bytes([len(context)]) +  # Context length (1 byte)
        context  # Context
    )
    
    return hkdf_expand(secret, hkdf_label, length)


def derive_early_secrets(psk=None):
    """Derive early secrets from PSK
    
    Used for 0-RTT mode (not implemented yet)
    """
    if psk is None:
        # Default PSK of zeros
        psk = b'\x00' * _HASH_LENGTH
    
    # Early secret = HKDF-Extract(0, PSK)
    early_secret = hkdf_extract(salt=b'\x00' * 32, ikm=psk)
    return early_secret