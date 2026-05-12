#!/usr/bin/env python3
"""
Tier 1 Integration Test
Tests the basic TLS 1.3 handshake and record layer integration
"""

import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from src.tls.protocol.handshake import TLSHandshake, ClientHello, ServerHello
from src.tls.protocol.record_layer import TLSRecordManager, ContentType
from src.tls.crypto.key_schedule import TLSKeySchedule
from src.tls.crypto.foundation import generate_ephemeral_key

def test_client_server_handshake():
    """Test a complete client-server handshake"""
    print("\n" + "="*60)
    print("TIER 1 INTEGRATION TEST: Client-Server Handshake")
    print("="*60)
    
    # Initialize client and server
    print("\n1. Initializing client and server...")
    client_handshake = TLSHandshake(is_server=False)
    server_handshake = TLSHandshake(is_server=True)
    
    client_record = TLSRecordManager(is_server=False)
    server_record = TLSRecordManager(is_server=True)
    
    print("   ✓ Client initialized")
    print("   ✓ Server initialized")
    
    # Client creates ClientHello
    print("\n2. Client creating ClientHello...")
    client_hello_bytes = client_handshake.create_client_hello()
    print(f"   ✓ ClientHello created: {len(client_hello_bytes)} bytes")
    
    # Server receives and processes ClientHello
    print("\n3. Server processing ClientHello...")
    server_hello_bytes, hs_complete = server_handshake.process_client_hello(client_hello_bytes)
    if server_hello_bytes:
        print(f"   ✓ ServerHello generated: {len(server_hello_bytes)} bytes")
    else:
        print("   ✗ Failed to generate ServerHello")
        return False
    
    # Client receives and processes ServerHello
    print("\n4. Client processing ServerHello...")
    client_processed = client_handshake.process_server_hello(server_hello_bytes)
    if client_processed:
        print("   ✓ ServerHello processed successfully")
    else:
        print("   ✗ Failed to process ServerHello")
        return False
    
    # Get handshake keys
    print("\n5. Deriving handshake keys...")
    try:
        client_keys = client_handshake.get_handshake_keys(is_server=False)
        server_keys = server_handshake.get_handshake_keys(is_server=True)
        
        # For message exchange:
        # - Client sends with client_keys (client handshake traffic secret)
        # - Server receives with client_keys (must derive from same secret)
        # - Server sends with server_keys (server handshake traffic secret)
        # - Client receives with server_keys (must derive from same secret)
        
        # Get keys for reading from the other party
        server_read_keys = server_handshake.key_schedule.derive_traffic_keys(
            server_handshake.key_schedule.client_handshake_traffic_secret
        )
        client_read_keys = client_handshake.key_schedule.derive_traffic_keys(
            client_handshake.key_schedule.server_handshake_traffic_secret
        )
        
        print(f"   ✓ Client keys: write_key={len(client_keys['key'])}, write_iv={len(client_keys['iv'])}")
        print(f"   ✓ Server keys: write_key={len(server_keys['key'])}, write_iv={len(server_keys['iv'])}")
    except Exception as e:
        print(f"   ✗ Failed to get handshake keys: {e}")
        return False
    
    # Enable encryption
    print("\n6. Enabling encryption...")
    try:
        client_record.enable_encryption("TLS_AES_256_GCM_SHA384", client_keys)
        server_record.enable_encryption("TLS_AES_256_GCM_SHA384", server_read_keys)
        print("   ✓ Client encryption enabled (write with client keys)")
        print("   ✓ Server encryption enabled (read with client keys)")
    except Exception as e:
        print(f"   ✗ Failed to enable encryption: {e}")
        return False
    
    # Test encrypted message exchange
    print("\n7. Testing encrypted message exchange...")
    try:
        # Client sends encrypted message
        message = b"Hello from client!"
        encrypted = client_record.send_application_data(message)
        print(f"   ✓ Client encrypted message: {len(message)} bytes -> {len(encrypted)} bytes")
        
        # Server receives encrypted message
        messages, remaining = server_record.receive_data(encrypted)
        if messages and messages[0][0] == 'application_data':
            decrypted = messages[0][1]
            if decrypted == message:
                print(f"   ✓ Server decrypted message: {decrypted}")
            else:
                print(f"   ✗ Decrypted message doesn't match: {decrypted}")
                return False
        else:
            print(f"   ✗ No application data received")
            return False
        
        # Now test server -> client (requires different keys)
        # Create new record managers for server->client direction
        client_record2 = TLSRecordManager(is_server=False)
        server_record2 = TLSRecordManager(is_server=True)
        
        # Enable encryption for server->client direction
        client_record2.enable_encryption("TLS_AES_256_GCM_SHA384", client_read_keys)
        server_record2.enable_encryption("TLS_AES_256_GCM_SHA384", server_keys)
        
        # Server sends encrypted message back
        response = b"Hello from server!"
        encrypted_response = server_record2.send_application_data(response)
        print(f"   ✓ Server encrypted message: {len(response)} bytes -> {len(encrypted_response)} bytes")
        
        # Client receives encrypted message
        messages, remaining = client_record2.receive_data(encrypted_response)
        if messages and messages[0][0] == 'application_data':
            decrypted_response = messages[0][1]
            if decrypted_response == response:
                print(f"   ✓ Client decrypted message: {decrypted_response}")
            else:
                print(f"   ✗ Decrypted response doesn't match: {decrypted_response}")
                return False
        else:
            print(f"   ✗ No application data received from server")
            return False
            
    except Exception as e:
        print(f"   ✗ Failed during message exchange: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    print("\n" + "="*60)
    print("✅ TIER 1 INTEGRATION TEST PASSED")
    print("="*60)
    return True


if __name__ == "__main__":
    try:
        success = test_client_server_handshake()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n✗ Test failed with exception: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
