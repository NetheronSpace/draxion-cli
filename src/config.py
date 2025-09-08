# -*- coding: utf-8 -*-
import os
import re
import json

# --- Directorios y Archivos ---
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) # Apunta a la carpeta 'cliente'
TEMP_DIR = os.path.join(BASE_DIR, "temp")
PROFILES_DIR = os.path.join(BASE_DIR, "profiles")
CONFIG_FILE = os.path.join(BASE_DIR, "client_config.json")
KEY_FILE_NAME = "private_key.pem"

# --- Red ---
SERVER_URL = ""

# --- Subidas/Descargas ---
CHUNK_SIZE = 16 * 1024 * 1024  # 16 MB

def ensure_dirs():
    """Asegura que los directorios base existan."""
    os.makedirs(TEMP_DIR, exist_ok=True)
    os.makedirs(PROFILES_DIR, exist_ok=True)

def get_profile_dir(username):
    """Obtiene el directorio de perfil para un usuario, creándolo si no existe."""
    safe_username = re.sub(r'[^a-zA-Z0-9_.-]', '_', username)
    profile_dir = os.path.join(PROFILES_DIR, safe_username)
    os.makedirs(profile_dir, exist_ok=True)
    return profile_dir

def get_available_profiles():
    """Lista los perfiles de usuario disponibles."""
    if not os.path.exists(PROFILES_DIR):
        return []
    profiles = [d for d in os.listdir(PROFILES_DIR) if os.path.isdir(os.path.join(PROFILES_DIR, d))]
    return profiles

def load_client_config():
    """Carga la configuración general del cliente."""
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}
    return {}

def save_client_config(config):
    """Guarda la configuración general del cliente."""
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=4)

# Asegurarse de que los directorios existan al importar el módulo
ensure_dirs()
