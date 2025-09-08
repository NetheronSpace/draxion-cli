# -*- coding: utf-8 -*-
import os
import json
import time
from .config import get_profile_dir

CACHE_FILE_NAME = 'metadata_cache.json'
CACHE_TTL_SECONDS = 300  # 5 minutos

def get_cache_path(username):
    """Obtiene la ruta completa al archivo de caché para un usuario."""
    profile_dir = get_profile_dir(username)
    return os.path.join(profile_dir, CACHE_FILE_NAME)

def load_cache(username):
    """
    Carga el caché desde un archivo JSON.
    Retorna los datos del caché si existe y es válido, sino None.
    """
    cache_path = get_cache_path(username)
    if not os.path.exists(cache_path):
        return None
    
    try:
        with open(cache_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (IOError, json.JSONDecodeError):
        return None

def save_cache(username, data):
    """Guarda los datos del caché en un archivo JSON."""
    cache_path = get_cache_path(username)
    try:
        with open(cache_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4)
    except IOError:
        # No es crítico si falla el guardado del caché
        pass

def get_cached_items(username, folder_id):
    """
    Obtiene los items de una carpeta específica desde el caché.
    Verifica si el caché para esa carpeta ha expirado (TTL).
    """
    folder_key = str(folder_id) if folder_id is not None else 'root'
    cache = load_cache(username)
    
    if not cache or folder_key not in cache:
        return None

    folder_data = cache[folder_key]
    timestamp = folder_data.get('timestamp', 0)

    if time.time() - timestamp > CACHE_TTL_SECONDS:
        # El caché ha expirado
        return None
        
    return folder_data.get('items')

def update_cache(username, folder_id, items):
    """
    Actualiza el caché para una carpeta específica con nuevos items.
    """
    folder_key = str(folder_id) if folder_id is not None else 'root'
    cache = load_cache(username) or {}
    
    cache[folder_key] = {
        'items': items,
        'timestamp': time.time()
    }
    
    save_cache(username, cache)
