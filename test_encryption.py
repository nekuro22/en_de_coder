"""
Quick test to verify encryption and decryption still work correctly
"""

import os
import sys
from file_encryptor import FileEncryptor

def test_encryption_decryption():
    """Test encryption and decryption"""
    print("Testing Encryption & Decryption...")
    print("=" * 50)
    
    # Create test file
    test_file = "test_input.txt"
    test_content = b"Dies ist ein Test! Geheim! \x00\xFF\x01\x02\x03"
    
    with open(test_file, 'wb') as f:
        f.write(test_content)
    
    print(f"✓ Created test file: {test_file}")
    print(f"  Content: {test_content[:50]}...")
    
    # Encrypt
    encrypted_file = "test_input.txt.encrypted"
    password = "TestPassword123!@#"
    algorithm = "1. AES-256-GCM (Sicherster)"
    
    encryptor = FileEncryptor()
    
    try:
        print(f"\n🔒 Encrypting with {algorithm}...")
        result = encryptor.encrypt_file(test_file, encrypted_file, password, algorithm)
        
        if result:
            encrypted_size = os.path.getsize(encrypted_file)
            original_size = os.path.getsize(test_file)
            print(f"✓ Encryption successful!")
            print(f"  Original: {original_size} bytes")
            print(f"  Encrypted: {encrypted_size} bytes")
        else:
            print("✗ Encryption failed")
            return False
    except Exception as e:
        print(f"✗ Encryption error: {str(e)}")
        return False
    
    # Decrypt
    decrypted_file = "test_output.txt"
    
    try:
        print(f"\n🔓 Decrypting...")
        result = encryptor.decrypt_file(encrypted_file, decrypted_file, password)
        
        if result:
            print(f"✓ Decryption successful!")
        else:
            print("✗ Decryption failed")
            return False
    except Exception as e:
        print(f"✗ Decryption error: {str(e)}")
        return False
    
    # Verify
    with open(decrypted_file, 'rb') as f:
        decrypted_content = f.read()
    
    if decrypted_content == test_content:
        print(f"\n✓ Verification PASSED!")
        print(f"  Original and decrypted content match perfectly!")
        success = True
    else:
        print(f"\n✗ Verification FAILED!")
        print(f"  Original:  {test_content[:50]}...")
        print(f"  Decrypted: {decrypted_content[:50]}...")
        success = False
    
    # Cleanup
    print("\nCleaning up test files...")
    for f in [test_file, encrypted_file, decrypted_file]:
        if os.path.exists(f):
            os.remove(f)
            print(f"  Removed: {f}")
    
    print("\n" + "=" * 50)
    if success:
        print("✓ ALL TESTS PASSED - Encryption & Decryption working!")
    else:
        print("✗ TESTS FAILED - There's an issue")
    
    return success

if __name__ == "__main__":
    success = test_encryption_decryption()
    sys.exit(0 if success else 1)
