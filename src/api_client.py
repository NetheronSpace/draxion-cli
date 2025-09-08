# -*- coding: utf-8 -*-
import requests
import json

from .config import SERVER_URL
from .i18n import t

class ClientConnectionError(Exception):
    """Custom exception for server connection errors."""
    pass

class APIClient:
    """
    Client to interact with the server's API.
    
    Manages the authentication token, session refresh, and
    centralizes all calls to the API endpoints.
    """
    def __init__(self, token=None, refresh_token_val=None):
        self.token = token
        self.refresh_token = refresh_token_val
        self.headers = {}
        if token:
            self.headers['Authorization'] = f'Bearer {token}'

    def set_token(self, token, refresh_token_val):
        """Sets a new session token."""
        self.token = token
        self.refresh_token = refresh_token_val
        self.headers['Authorization'] = f'Bearer {token}'

    def _perform_refresh(self):
        """Attempts to refresh the session token using the refresh token."""
        if not self.refresh_token:
            return False
        
        url = f"{SERVER_URL}/refresh"
        headers = {'Authorization': f'Bearer {self.refresh_token}'}
        try:
            response = requests.post(url, headers=headers, timeout=10)
            if response.status_code == 200:
                new_token = response.json()['token']
                self.set_token(new_token, self.refresh_token) # Asumimos que el refresh token no cambia
                print(f"\n{t('session_refreshed')}")
                return True
            return False
        except requests.exceptions.RequestException:
            return False

    def _make_request(self, method, url, needs_auth=True, timeout=15, **kwargs):
        """Makes a request to the API, handling authentication and token refresh."""
        if needs_auth and not self.token:
            # No se puede hacer una llamada autenticada sin token
            return None

        # Añadir cabeceras de autenticación si es necesario
        if needs_auth:
            kwargs.setdefault('headers', {}).update(self.headers)

        full_url = f"{SERVER_URL}{url}"
        try:
            response = requests.request(method, full_url, timeout=timeout, **kwargs)
        except requests.exceptions.RequestException:
            raise ClientConnectionError()

        # Si la petición falla por token expirado, intentar refrescarlo
        if needs_auth and response.status_code == 401:
            print(f"\n{t('token_expired')}")
            if self._perform_refresh():
                # Reintentar la petición con el nuevo token
                kwargs['headers'].update(self.headers)
                try:
                    response = requests.request(method, full_url, timeout=timeout, **kwargs)
                except requests.exceptions.RequestException:
                    raise ClientConnectionError()
            else:
                print(f"\n{t('session_refresh_failed')}")

        return response

    # --- Auth and Registration Endpoints ---
    def verificar_usuario(self, username):
        return self._make_request('get', f"/verificar-usuario/{username}", needs_auth=False)

    def verificar_pin(self, pin):
        return self._make_request('post', "/verificar-pin", json={'pin': pin})
    
    def registrar(self, username, password, pin):
        data = {'username': username, 'password': password, 'pin': pin}
        return self._make_request('post', "/registro", needs_auth=False, json=data)

    def registro_commit(self, username, signature_dump):
        data = {'username': username, 'signature_dump': signature_dump}
        return self._make_request('post', "/registro/commit", needs_auth=False, json=data)

    def login_start(self, username):
        return self._make_request('post', "/login", needs_auth=False, json={'username': username})

    def login_verify(self, username, proof_dump, nonce):
        data = {'username': username, 'proof_dump': proof_dump, 'nonce': nonce}
        return self._make_request('post', "/login/verify", needs_auth=False, json=data)

    def obtener_estado(self):
        return self._make_request('get', "/api/status")

    # --- File and Folder Management Endpoints ---
    def obtener_arbol_archivos(self, carpeta_id=None):
        params = {'carpeta_id': carpeta_id} if carpeta_id else {}
        return self._make_request('get', "/archivos", params=params)

    def obtener_todos_los_archivos(self):
        """Gets a flat list of all the user's files."""
        return self._make_request('get', "/archivos/todos")
    
    def crear_carpeta(self, nombre, parent_id=None):
        data = {'nombre': nombre, 'parent_id': parent_id}
        return self._make_request('post', "/carpetas", json=data)

    def renombrar_item(self, item_id, item_type, nuevo_nombre):
        url = f"/{item_type}s/{item_id}/renombrar"
        return self._make_request('put', url, json={'nuevo_nombre': nuevo_nombre})

    def mover_item(self, item_id, item_type, carpeta_destino_id):
        url = f"/{item_type}s/{item_id}/mover"
        return self._make_request('put', url, json={'target_id': carpeta_destino_id})

    def eliminar_archivo(self, archivo_id):
        return self._make_request('delete', f"/archivo/{archivo_id}")

    def eliminar_carpeta(self, carpeta_id):
        return self._make_request('delete', f"/carpetas/{carpeta_id}")

    # --- Upload/Download Endpoints ---
    def iniciar_subida(self, nombre_real, tamano_total, hash_archivo, firma, carpeta_id=None):
        data = {
            'nombre_real': nombre_real, 'tamano_total': tamano_total,
            'hash_archivo': hash_archivo, 'firma': firma, 'carpeta_id': carpeta_id
        }
        return self._make_request('post', "/upload/initiate", json=data)

    def estado_subida(self, upload_id):
        return self._make_request('get', f"/upload/status/{upload_id}")

    def subir_chunk(self, upload_id, chunk_number, chunk_data):
        url = f"/upload/chunk/{upload_id}/{chunk_number}"
        headers = {'Content-Type': 'application/octet-stream'}
        return self._make_request('post', url, data=chunk_data, headers=headers)

    def completar_subida(self, upload_id):
        return self._make_request('post', f"/upload/complete/{upload_id}", timeout=300)

    def descargar_chunk(self, archivo_id, range_header=None):
        headers = {'Range': range_header} if range_header else {}
        return self._make_request('get', f"/descargar/{archivo_id}", headers=headers, stream=True)

    # --- Cryptography and Key Endpoints ---
    def obtener_clave_archivo(self, archivo_id):
        return self._make_request('get', f"/clave/{archivo_id}")

    def obtener_clave_publica(self, username):
        return self._make_request('get', f"/usuario/{username}/clave-publica")

    def rotar_claves(self, clave_privada_actual):
        return self._make_request('post', "/rotar-claves", json={'clave_privada_actual': clave_privada_actual})

    # --- Sharing Endpoints ---
    def compartir_archivo(self, archivo_id, usuario_id_destino, clave_cifrada):
        data = {'archivo_id': archivo_id, 'usuario_id_destino': usuario_id_destino, 'clave_cifrada': clave_cifrada}
        return self._make_request('post', "/compartir", json=data)

    def obtener_comparticiones_pendientes(self):
        return self._make_request('get', "/compartir/pendientes")

    def aceptar_comparticion(self, share_id):
        return self._make_request('post', f"/compartir/aceptar/{share_id}")

    def rechazar_comparticion(self, share_id):
        return self._make_request('post', f"/compartir/rechazar/{share_id}")

    def obtener_mis_archivos_compartidos(self):
        return self._make_request('get', "/compartir/mis-archivos")

    def obtener_accesos_de_archivo(self, archivo_id):
        return self._make_request('get', f"/compartir/archivo/{archivo_id}/accesos")

    def revocar_acceso(self, archivo_id, usuario_id):
        return self._make_request('delete', f"/compartir/archivo/{archivo_id}/acceso/{usuario_id}")

    def revocar_acceso_propio(self, archivo_id):
        return self._make_request('delete', f"/compartir/acceso/{archivo_id}")

    # --- Trash Endpoints ---
    def obtener_papelera(self):
        """Gets the list of files in the trash."""
        return self._make_request('get', "/papelera")

    def restaurar_archivo(self, archivo_id):
        """Restores a file from the trash."""
        return self._make_request('post', f"/papelera/restaurar/{archivo_id}")

    def eliminar_permanentemente(self, archivo_id):
        """Permanently deletes a file from the trash."""
        return self._make_request('delete', f"/papelera/eliminar-permanente/{archivo_id}")

    # --- Other Endpoints ---
    def obtener_auditoria(self, pagina=1):
        return self._make_request('get', "/auditoria", params={'page': pagina})

    def obtener_estado_tarea(self, task_id):
        """Checks the status of a Celery task on the backend."""
        return self._make_request('get', f"/task/{task_id}/status")