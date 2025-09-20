#!/usr/bin/env python3
import os
import sys
import base64
import hashlib
import binascii
from cryptography.fernet import Fernet, InvalidToken

# Configuration
PPL_FILE_PATH = 'ppl.txt'

try:
    import pwinput
except ImportError:
    print("Please install pwinput: pip install pwinput")
    sys.exit(1)

def CREATE_PPL():
    if not os.path.exists(PPL_FILE_PATH):
        with open('ppl.txt', 'w') as file:
            pass

# --- Encryption Functions ---
def STRING_TO_KEY(password, salt):
    """Generate a Fernet key from a password using provided salt"""
    hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    fernet_key = base64.urlsafe_b64encode(hash)
    return fernet_key


def ENCRYPT(content, key):
    """Encrypt content using password-derived key"""
    salt = os.urandom(16)
    fernet_key = STRING_TO_KEY(key, salt)
    fernet = Fernet(fernet_key)
    crypt_text = fernet.encrypt(content.encode())
    return base64.urlsafe_b64encode(salt + crypt_text).decode()


def DECRYPT(content, key):
    """Decrypt content using password-derived key"""
    try:
        data = base64.urlsafe_b64decode(content.encode())
        if len(data) < 16:
            return None

        salt, crypt_text = data[:16], data[16:]
        fernet_key = STRING_TO_KEY(key, salt)
        fernet = Fernet(fernet_key)
        return fernet.decrypt(crypt_text).decode()

    except (binascii.Error, ValueError, InvalidToken):
        return None
    except Exception as e:
        print(f"Unexpected error in DECRYPT: {e}")
        return None


def PASSWORD():
    """Prompt for password securely"""
    password = pwinput.pwinput(mask='*', prompt='Password >>> ').strip()
    return password


def CLEAR_TERMINAL():
    """Clear terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')


def LOGO():
    """Display program logo"""
    print('''
       ___  ___  __ _ 
      / _ \/ _ \/  ' \\
     / .__/ .__/_/_/_/
    /_/  /_/              
    ''')


# --- PPM Functions ---
def PPM():
    """Password and Personal Manager main menu"""
    while True:
        CLEAR_TERMINAL()
        LOGO()
        print('''
    [1] Add a new service
    [2] Edit a service
    [3] Delete a service
    [4] Exit
        ''')

        try:
            choice = int(input('[PPM] Select an option >>> '))

            if choice == 1:
                PPM_ADD()
            elif choice == 2:
                PPM_EDIT()
            elif choice == 3:
                PPM_DELETE()
            elif choice == 4:
                input('[PPM] Goodbye. Press Enter to continue')
                break
            else:
                input('[PPM] Invalid option. Press Enter to continue')

        except ValueError:
            input('[PPM] Please enter a valid number. Press Enter to continue')


def PPM_ADD():
    """Add a new encrypted service entry"""
    try:
        CLEAR_TERMINAL()
        LOGO()
        print('[PPM(add)] Type "done" to finish\n')

        text_parts = []
        while True:
            desc = input('[PPM(add)] Description >>> ').strip()
            if desc.lower() == 'done':
                break

            value = input('[PPM(add)] Value >>> ').strip()
            if not desc or not value:
                print("Description and value cannot be empty")
                continue

            text_parts.append(f"{desc}:{value}|")

        if not text_parts:
            input('[PPM] No service added. Press Enter to continue')
            return

        text = ''.join(text_parts)[:-1]  # Remove trailing |

        password = PASSWORD()
        if not password:
            return

        encrypted_text = ENCRYPT(text, password)
        if not encrypted_text:
            input('[PPM] Failed to encrypt. Press Enter to continue')
            return

        with open(PPL_FILE_PATH, 'a', encoding='utf-8') as file:
            file.write(encrypted_text + '\n')

        input('[PPM] Service added successfully. Press Enter to continue')

    except Exception as e:
        print(f"Error: {e}")
        input('[PPM] Operation failed. Press Enter to continue')


def PPM_EDIT():
    """Edit an existing service entry"""
    try:
        password = PASSWORD()
        if not password:
            return

        if not os.path.exists(PPL_FILE_PATH):
            print('[PPM] No services found')
            input('Press Enter to continue')
            return

        with open(PPL_FILE_PATH, 'r', encoding='utf-8') as file:
            lines = [line.strip() for line in file if line.strip()]

        if not lines:
            print('[PPM] No services found')
            input('Press Enter to continue')
            return

        # Decrypt all entries for display
        decrypted_lines = []
        successful_decrypts = 0
        for line in lines:
            decrypted = DECRYPT(line, password)
            if decrypted:
                decrypted_lines.append(decrypted)
                successful_decrypts += 1

        if successful_decrypts == 0:
            print("[PPM] Failed to decrypt any entries (wrong password?)")
            input('Press Enter to continue')
            return

        # Display all services
        print('\n[PPM] Your Services:')
        for i, line in enumerate(decrypted_lines):
            parts = line.split('|')
            if parts:
                print(f'[{i + 1}] {parts[0]}|{parts[1]}')

        # Select service to edit
        try:
            choice = int(input('\n[PPM] Select service to edit (number) >>> ')) - 1
            if choice < 0 or choice >= len(decrypted_lines):
                print("Invalid selection")
                return
        except ValueError:
            print("Please enter a valid number")
            return

        # Edit the selected service
        print('\n[PPM] Current service details:')
        print(decrypted_lines[choice].replace('|', '\n'))
        print('\n[PPM] Enter new details (type "done" to finish)')

        new_parts = []
        while True:
            desc = input('[PPM(edit)] New description >>> ').strip()
            if desc.lower() == 'done':
                break
            value = input('[PPM(edit)] New value >>> ').strip()
            if not desc or not value:
                print("Description and value cannot be empty")
                continue
            new_parts.append(f"{desc}:{value}")

        if not new_parts:
            print("No changes made")
            return

        new_text = "|".join(new_parts)
        encrypted_text = ENCRYPT(new_text, password)
        if not encrypted_text:
            print("Failed to encrypt new entry")
            return

        # Find the corresponding encrypted line to replace
        original_encrypted_line = None
        for i, line in enumerate(lines):
            decrypted_test = DECRYPT(line, password)
            if decrypted_test == decrypted_lines[choice]:
                original_encrypted_line = i
                break

        if original_encrypted_line is not None:
            lines[original_encrypted_line] = encrypted_text
            with open(PPL_FILE_PATH, 'w', encoding='utf-8') as file:
                file.write('\n'.join(lines) + '\n')
            input('[PPM] Service updated successfully. Press Enter to continue')
        else:
            print("Could not find the original entry to update")
            input('Press Enter to continue')

    except Exception as e:
        print(f"Error: {e}")
        input('[PPM] Operation failed. Press Enter to continue')


def PPM_DELETE():
    """Delete a service entry"""
    try:
        password = PASSWORD()
        if not password:
            return

        if not os.path.exists(PPL_FILE_PATH):
            print('[PPM] No services found')
            input('Press Enter to continue')
            return

        with open(PPL_FILE_PATH, 'r', encoding='utf-8') as file:
            lines = [line.strip() for line in file if line.strip()]

        if not lines:
            print('[PPM] No services found')
            input('Press Enter to continue')
            return

        # Decrypt all entries for display
        decrypted_lines = []
        successful_decrypts = 0
        for line in lines:
            decrypted = DECRYPT(line, password)
            if decrypted:
                decrypted_lines.append(decrypted)
                successful_decrypts += 1

        if successful_decrypts == 0:
            print("[PPM] Failed to decrypt any entries (wrong password?)")
            input('Press Enter to continue')
            return

        # Display all services
        print('\n[PPM] Your Services:')
        for i, line in enumerate(decrypted_lines):
            parts = line.split('|')
            if parts:
                print(f'[{i + 1}] {parts[0]}')

        # Select service to delete
        try:
            choice = int(input('\n[PPM] Select service to delete (number) >>> ')) - 1
            if choice < 0 or choice >= len(decrypted_lines):
                print("Invalid selection")
                return
        except ValueError:
            print("Please enter a valid number")
            return

        # Confirm deletion
        confirm = input(f'\n[PPM] Delete this service? [{decrypted_lines[choice][:50]}...] (y/n) >>> ').lower()
        if confirm != 'y':
            print('Deletion cancelled')
            return

        # Find the corresponding encrypted line to delete
        lines_to_keep = []
        for i, line in enumerate(lines):
            decrypted_test = DECRYPT(line, password)
            if decrypted_test != decrypted_lines[choice]:
                lines_to_keep.append(line)

        with open(PPL_FILE_PATH, 'w', encoding='utf-8') as file:
            file.write('\n'.join(lines_to_keep) + '\n')

        input('[PPM] Service deleted successfully. Press Enter to continue')

    except Exception as e:
        print(f"Error: {e}")
        input('[PPM] Operation failed. Press Enter to continue')


# --- Main Execution ---
if __name__ == "__main__":
    CREATE_PPL()
    PPM()