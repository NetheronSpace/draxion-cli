# -*- coding: utf-8 -*-
import base64
import hashlib
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

from .config import get_profile_dir, KEY_FILE_NAME, CHUNK_SIZE
from .ui import t, E, R

def generar_par_claves():
    """Generates a new 4096-bit RSA key pair (public and private)."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    pem_privado = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
    pem_publico = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return pem_publico, pem_privado

def calcular_hash_archivo(archivo_path):
    """Calculates the SHA256 hash of a file by processing it in chunks."""
    sha256 = hashlib.sha256()
    with open(archivo_path, 'rb') as f:
        while chunk := f.read(CHUNK_SIZE):
            sha256.update(chunk)
    return sha256

def firmar_hash(hash_bytes, clave_privada_pem):
    """Signs a hash using a PEM-encoded private key."""
    private_key = serialization.load_pem_private_key(
        clave_privada_pem.encode(),
        password=None,
        backend=default_backend()
    )
    firma = private_key.sign(
        hash_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(firma).decode()

def descifrar_clave_aes(clave_cifrada_b64, private_key_pem):
    """Decrypts an AES key (wrapped with RSA-OAEP) using the private key."""
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=None,
        backend=default_backend()
    )
    clave_cifrada = base64.b64decode(clave_cifrada_b64)
    clave_aes = private_key.decrypt(
        clave_cifrada,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return clave_aes

def descifrar_archivo_fernet(archivo_cifrado_path, archivo_descifrado_path, clave_fernet):
    fernet = Fernet(clave_fernet)
    with open(archivo_cifrado_path, 'rb') as f_cifrado:
        with open(archivo_descifrado_path, 'wb') as f_descifrado:
            while chunk := f_cifrado.read(CHUNK_SIZE):
                if chunk:
                    try:
                        descifrado = fernet.decrypt(chunk)
                        f_descifrado.write(descifrado)
                    except Exception:
                        return False
    return True

def cargar_clave_privada(username, password):
    """Loads and decrypts a user's private key from their profile."""
    profile_dir = get_profile_dir(username)
    key_path = os.path.join(profile_dir, KEY_FILE_NAME)

    if not os.path.exists(key_path):
        print(f"{t('private_key_not_found')}: {key_path}")
        return None
    try:
        with open(key_path, 'rb') as f:
            encrypted_pem = f.read()
        
        private_key_obj = serialization.load_pem_private_key(
            encrypted_pem,
            password=password.encode(),
            backend=default_backend()
        )
        
        # Returns the key unencrypted in PEM string format
        return private_key_obj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()

    except (ValueError, TypeError):
        print(f"\n{E}{t('private_key_decryption_error')}{R}")
        return None
    except Exception as e:
        print(f"{t('error_loading_private_key')}: {str(e)}")
        return None

def guardar_clave_privada(username, clave_pem, password):
    """Encrypts and saves a private key to a user's profile."""
    try:
        profile_dir = get_profile_dir(username)
        key_path = os.path.join(profile_dir, KEY_FILE_NAME)

        private_key_obj = serialization.load_pem_private_key(
            clave_pem.encode(),
            password=None,
            backend=default_backend()
        )
        
        encrypted_pem = private_key_obj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
        )
        
        with open(key_path, 'wb') as f:
            f.write(encrypted_pem)
        return True
    except Exception as e:
        print(f"{t('error_saving_key')}: {str(e)}")
        return False
