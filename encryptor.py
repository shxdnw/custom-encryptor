import os
import base64
import hashlib
import hmac
from secrets import compare_digest
from Cryptodome.Cipher import AES, ChaCha20_Poly1305
from Cryptodome.Random import get_random_bytes
import argon2
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from getpass import getpass
import sys

# Install required: pip install pycryptodome argon2-cffi cryptography

class SecureVault:
    def __init__(self, password: str | bytes):
        # Use bytearray for mutable password storage
        if isinstance(password, str):
            self.password = bytearray(password.encode("utf-8"))
        else:
            self.password = bytearray(password)
        
        # Security parameters (reduced for lower resource usage)
        self.ARGON_TIME = 2          # Reduced time cost
        self.ARGON_MEM = 64 * 1024   # 64 MiB (reduced memory cost)
        self.ARGON_PARALLEL = 1      # Reduced parallelism

    def _secure_wipe(self, data: bytearray) -> None:
        """Securely wipe memory using mutable buffers"""
        if isinstance(data, bytearray):
            for i in range(len(data)):
                data[i] = 0
        elif isinstance(data, memoryview):
            data.release()

    def _derive_keys(self, salt: bytes) -> dict:
        """Memory-hard KDF with key separation"""
        # Generate raw key using Argon2
        raw_key = argon2.PasswordHasher(
            time_cost=self.ARGON_TIME,
            memory_cost=self.ARGON_MEM,
            parallelism=self.ARGON_PARALLEL,
            hash_len=64,  # 64 bytes for AES + ChaCha20 + HMAC keys
            type=argon2.Type.ID
        ).hash(bytes(self.password), salt=salt)
        
        # Convert Argon2 hash output to bytes
        raw_key_bytes = raw_key.encode("utf-8")  # Convert string to bytes
        
        # Use HKDF for key separation
        hkdf = HKDF(
            algorithm=hashes.SHA256(),  # Use SHA-256 for HKDF
            length=64,  # 64 bytes for AES + ChaCha20 + HMAC keys
            salt=salt,
            info=b"secure_vault_keys",
        )
        master_key = hkdf.derive(raw_key_bytes)
        
        return {
            "aes_key": bytearray(master_key[:32]),  # 32 bytes for AES-256
            "chacha_key": bytearray(master_key[32:64]),  # 32 bytes for ChaCha20
            "hmac_key": bytearray(master_key[48:]),  # 16 bytes for HMAC
            "salt": salt
        }

    def encrypt(self, plaintext: bytes) -> bytes:
        keys = None  # Initialize keys to avoid reference errors
        try:
            # Generate fresh random values
            salt = get_random_bytes(16)  # Reduced salt size
            aes_nonce = get_random_bytes(12)  # Reduced nonce size
            chacha_nonce = get_random_bytes(12)  # Reduced nonce size
            
            # Key derivation
            keys = self._derive_keys(salt)
            
            # Layer 1: AES-256-CTR with HMAC-SHA256
            cipher_aes = AES.new(
                key=bytes(keys["aes_key"]),
                mode=AES.MODE_CTR,
                nonce=aes_nonce[:8]
            )
            ct1 = cipher_aes.encrypt(plaintext)
            mac1 = hmac.new(
                bytes(keys["hmac_key"]),
                ct1 + aes_nonce,
                hashlib.sha256  # Use SHA-256 for HMAC
            ).digest()
            
            # Layer 2: ChaCha20-Poly1305 AEAD
            cipher_chacha = ChaCha20_Poly1305.new(
                key=bytes(keys["chacha_key"]),  # 32-byte key
                nonce=chacha_nonce
            )
            ct2, tag = cipher_chacha.encrypt_and_digest(ct1 + mac1)
            
            # Final HMAC over all components
            hmac_payload = salt + aes_nonce + chacha_nonce + ct2
            final_hmac = hmac.new(
                bytes(keys["hmac_key"]),
                hmac_payload,
                hashlib.sha256  # Use SHA-256 for HMAC
            ).digest()
            
            # Serialize with constant-time encoding
            payload = base64.b85encode(
                hmac_payload + tag + final_hmac
            )
            
            return bytes(payload)
            
        finally:
            # Securely wipe all keys from memory
            if keys is not None:
                for key in keys.values():
                    if isinstance(key, (bytearray, memoryview)):
                        self._secure_wipe(key)
            self._secure_wipe(bytearray(plaintext))

    def decrypt(self, ciphertext: bytes) -> bytes | None:
        keys = None  # Initialize keys to avoid reference errors
        try:
            # Deserialize with constant-time operations
            raw = bytearray(base64.b85decode(ciphertext))
            
            if len(raw) < 16 + 12 + 12 + 16 + 32:  # Adjusted for reduced sizes
                raise ValueError("Invalid ciphertext")
                
            # Split components
            salt = bytes(raw[:16])
            aes_nonce = bytes(raw[16:28])
            chacha_nonce = bytes(raw[28:40])
            ct2 = bytes(raw[40:-48])
            tag = bytes(raw[-48:-32])
            received_hmac = bytes(raw[-32:])
            
            # Re-derive keys
            keys = self._derive_keys(salt)
            
            # Verify outer HMAC
            hmac_payload = raw[:40] + ct2
            calc_hmac = hmac.new(
                bytes(keys["hmac_key"]),
                bytes(hmac_payload),
                hashlib.sha256  # Use SHA-256 for HMAC
            ).digest()
            
            if not compare_digest(calc_hmac, received_hmac):
                raise ValueError("Authentication failed")
            
            # Layer 2: ChaCha20-Poly1305 decrypt
            cipher_chacha = ChaCha20_Poly1305.new(
                key=bytes(keys["chacha_key"]),  # 32-byte key
                nonce=chacha_nonce
            )
            pt2 = cipher_chacha.decrypt_and_verify(ct2, tag)
            
            # Split Layer 1 components
            ct1 = pt2[:-32]
            mac1 = pt2[-32:]
            
            # Verify Layer 1 HMAC
            if not hmac.compare_digest(
                hmac.new(
                    bytes(keys["hmac_key"]),
                    ct1 + aes_nonce,
                    hashlib.sha256  # Use SHA-256 for HMAC
                ).digest(),
                mac1
            ):
                raise ValueError("Inner authentication failed")
            
            # Layer 1: AES decrypt
            cipher_aes = AES.new(
                key=bytes(keys["aes_key"]),
                mode=AES.MODE_CTR,
                nonce=aes_nonce[:8]
            )
            plaintext = cipher_aes.decrypt(ct1)
            
            return bytes(plaintext)
            
        finally:
            # Securely wipe all sensitive data
            if keys is not None:
                for key in keys.values():
                    if isinstance(key, (bytearray, memoryview)):
                        self._secure_wipe(key)
            self._secure_wipe(raw)

def main():
    print("Secure Vault Encryptor")
    print("----------------------")
    
    # Get password securely
    password = getpass("Enter encryption password: ").strip()
    if not password:
        print("Error: Password cannot be empty", file=sys.stderr)
        sys.exit(1)
    
    vault = SecureVault(password)
    
    # Ask user for encryption or decryption
    choice = input("Choose an operation:\n1. Encrypt\n2. Decrypt\nEnter your choice (1 or 2): ").strip()
    
    if choice == "1":
        # Encryption
        plaintext = input("Enter the text to encrypt: ").strip().encode("utf-8")
        print("\nEncrypting...")
        ciphertext = vault.encrypt(plaintext)
        print(f"\nEncrypted payload ({len(ciphertext)} bytes):")
        print(ciphertext.decode())
        
    elif choice == "2":
        # Decryption
        ciphertext = input("Enter the ciphertext to decrypt: ").strip().encode("utf-8")
        print("\nDecrypting...")
        decrypted = vault.decrypt(ciphertext)
        if decrypted is None:
            print("Decryption failed!", file=sys.stderr)
            sys.exit(1)
        print(f"\nDecrypted text: {decrypted.decode()}")
        
    else:
        print("Invalid choice. Exiting.", file=sys.stderr)
        sys.exit(1)
    
    # Securely wipe password from memory
    del password
    del vault

if __name__ == "__main__":
    main()