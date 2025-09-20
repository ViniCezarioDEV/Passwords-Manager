#!/usr/bin/env python3
import os
import sys
import base64
import hashlib
import binascii
from cryptography.fernet import Fernet, InvalidToken
try:
    import pwinput  # For secure password input
except ImportError:
    print("Please install pwinput: pip install pwinput")
    sys.exit(1)


PPL_FILE_PATH = "ppl.txt"

def CHECK_PPL():
    if not os.path.exists(PPL_FILE_PATH):
        print('ppl.txt file not exists')
        sys.exit(1)
        

# --- Encryption Functions ---
def STRING_TO_KEY(password, salt=None):
    """Generate a Fernet key from a password"""
    if salt is None:
        salt = os.urandom(16)
    hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    fernet_key = base64.urlsafe_b64encode(hash)
    return fernet_key, salt

def ENCRYPT(content, key):
    """Encrypt content using password-derived key"""
    fernet_key, salt = STRING_TO_KEY(key)
    fernet = Fernet(fernet_key)
    crypt_text = fernet.encrypt(content.encode())
    return base64.urlsafe_b64encode(salt + crypt_text).decode()

def DECRYPT(content, key):
    """Decrypt content using password-derived key"""
    try:
        data = base64.urlsafe_b64decode(content.encode())
        if len(data) < 16:  # Minimum 16-byte salt
            raise ValueError("Invalid encrypted data")
        
        salt, crypt_text = data[:16], data[16:]
        fernet_key, _ = STRING_TO_KEY(key, salt)
        fernet = Fernet(fernet_key)
        
        return fernet.decrypt(crypt_text).decode()
    
    except (binascii.Error, ValueError):
        return None
    except InvalidToken:
        return None
    except Exception:
        return None

def PASSWORD():
    """Prompt for password securely"""
    password = pwinput.pwinput(mask='*', prompt='Password >>> ').strip()
    return password

# --- Core Search Function ---
def SPP(search_terms):
    """Search encrypted data for matching entries"""
    try:
        if not os.path.exists(PPL_FILE_PATH):
            with open(PPL_FILE_PATH, 'w', encoding='utf-8') as f:
                return []

        with open(PPL_FILE_PATH, 'r', encoding='utf-8') as f:
            encrypted_lines = [line.strip() for line in f if line.strip()]

        if not encrypted_lines:
            return []

        password = PASSWORD()
        if not password:
            return []

        results = []
        seen = set()
        
        for encrypted in encrypted_lines:
            decrypted = DECRYPT(encrypted, password)
            if decrypted and decrypted not in seen:
                if all(term.lower() in decrypted.lower() for term in search_terms):
                    results.append(decrypted)
                    seen.add(decrypted)

        return results

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return []

# --- Command Line Interface ---
if __name__ == "__main__":
    CHECK_PPL()
    
    if len(sys.argv) < 2:
        print("Usage: spp <term1> <term2> ...", file=sys.stderr)
        print("Example: spp email john", file=sys.stderr)
        sys.exit(1)

    search_terms = sys.argv[1:]
    matches = SPP(search_terms)

    if not matches:
        print("No results found.", file=sys.stderr)
        sys.exit(0)

    for result in matches:
        print(result)
