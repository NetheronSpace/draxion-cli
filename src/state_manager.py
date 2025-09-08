# -*- coding: utf-8 -*-
import os
import json
from .config import get_profile_dir

def _load_state_file(state_file_path):
    """Función auxiliar para cargar un archivo de estado JSON."""
    if os.path.exists(state_file_path):
        with open(state_file_path, 'r') as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                pass
    return {}

def _save_state_file(state_file_path, state_data):
    """Función auxiliar para guardar datos en un archivo de estado JSON."""
    with open(state_file_path, 'w') as f:
        json.dump(state_data, f)

# --- Gestión de Estado de Subidas ---

def guardar_estado_subida(username, file_hash, upload_id):
    profile_dir = get_profile_dir(username)
    state_file = os.path.join(profile_dir, "upload_state.json")
    state = _load_state_file(state_file)
    state[file_hash] = upload_id
    _save_state_file(state_file, state)

def cargar_estado_subida(username, file_hash):
    profile_dir = get_profile_dir(username)
    state_file = os.path.join(profile_dir, "upload_state.json")
    state = _load_state_file(state_file)
    return state.get(file_hash)

def limpiar_estado_subida(username, file_hash):
    profile_dir = get_profile_dir(username)
    state_file = os.path.join(profile_dir, "upload_state.json")
    state = _load_state_file(state_file)
    if file_hash in state:
        del state[file_hash]
        _save_state_file(state_file, state)

# --- Gestión de Estado de Descargas ---

def guardar_estado_descarga(username, archivo_id, temp_path):
    profile_dir = get_profile_dir(username)
    state_file = os.path.join(profile_dir, "download_state.json")
    state = _load_state_file(state_file)
    state[str(archivo_id)] = temp_path
    _save_state_file(state_file, state)

def cargar_estado_descarga(username, archivo_id):
    profile_dir = get_profile_dir(username)
    state_file = os.path.join(profile_dir, "download_state.json")
    state = _load_state_file(state_file)
    return state.get(str(archivo_id))

def limpiar_estado_descarga(username, archivo_id):
    profile_dir = get_profile_dir(username)
    state_file = os.path.join(profile_dir, "download_state.json")
    state = _load_state_file(state_file)
    if str(archivo_id) in state:
        del state[str(archivo_id)]
        _save_state_file(state_file, state)

# --- Gestión de Sesión ---

def save_session(username, session_data):
    profile_dir = get_profile_dir(username)
    session_file = os.path.join(profile_dir, "session.json")
    with open(session_file, 'w') as f:
        json.dump(session_data, f)

def load_session(username):
    profile_dir = get_profile_dir(username)
    session_file = os.path.join(profile_dir, "session.json")
    if os.path.exists(session_file):
        with open(session_file, 'r') as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return None
    return None

def clear_session(username):
    profile_dir = get_profile_dir(username)
    session_file = os.path.join(profile_dir, "session.json")
    if os.path.exists(session_file):
        os.remove(session_file)
