# -*- coding: utf-8 -*-
import getpass
import time
import json
import uuid
import os
import requests

from .ui import (
    clear_screen, print_title, print_menu, print_user_banner, 
    AnimacionSpinner, t, T, I, S, E, R, O, print_api_error, bytes_a_legible, WIDTH
)
from .api_client import ClientConnectionError
from .crypto import guardar_clave_privada, cargar_clave_privada, descifrar_clave_aes, generar_par_claves
from .state_manager import save_session, clear_session, load_session
from .config import save_client_config, load_client_config, get_profile_dir, KEY_FILE_NAME, get_available_profiles
from .file_handler import (
    subir_archivo, descargar_archivo, compartir_archivo, 
    descargar_archivos_concurrentemente, seleccionar_ruta_grafico, seleccionar_ruta_manual
)
from .sss import dividir_clave_sss, recuperar_clave_sss
from .cache_manager import get_cached_items, update_cache
from .tui import FileExplorerApp

# Advanced crypto dependencies used in workflows
from noknow.core import ZKProof, ZKParameters
from cryptography.hazmat.primitives import serialization

from prompt_toolkit import prompt
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.shortcuts import CompleteStyle


def registrar(api_client):
    try:
        clear_screen()
        print_title("user_registration_title")
        username = None
        while not username:
            username_input = input(f"{I}» {t('user')}: {R}")
            if not username_input.strip():
                print(f"\n{E}{t('username_cannot_be_empty')}{R}")
                continue
            username = username_input
            
            try:
                with AnimacionSpinner(t('verifying_user'), show_completion_message=False, min_duration=1):
                    response = api_client.verificar_usuario(username)
            except ClientConnectionError:
                print(f"\n{E}{t('server_not_responding')}{R}")
                input(f"\n{O}{t('press_enter')}{R}")
                return

            if response.status_code == 200:
                if response.json()['disponible']:
                    break
                print(f"\n{E}{t('user_unavailable')}{R}")
                username = None
            else:
                print_api_error(response, t('error_verifying_user'))
                input(f"\n{O}{t('press_enter')}{R}")
                return

        password = None
        while not password:
            clear_screen()
            print_title("user_registration_title")
            print(f"{I}» {t('user')}: {username}{R}")
            password = getpass.getpass(f"{I}» {t('account_password')}: {R}")
            password2 = getpass.getpass(f"{I}» {t('confirm_account_password')}: {R}")
            if password != password2:
                print(f"\n{E}{t('passwords_do_not_match')}{R}")
                password = None
                input(f"\n{O}{t('press_enter')}{R}")
                continue
            if len(password) < 8:
                print(f"\n{E}{t('password_length_error')}{R}")
                password = None
                input(f"\n{O}{t('press_enter')}{R}")

        pin = None
        while not pin:
            clear_screen()
            print_title("user_registration_title")
            print(f"{I}» {t('user')}: {username}{R}")
            pin = getpass.getpass(f"{I}» {t('account_pin')}: {R}")
            pin2 = getpass.getpass(f"{I}» {t('confirm_pin')}: {R}")
            if pin != pin2:
                print(f"\n{E}{t('pins_do_not_match')}{R}")
                pin = None
                input(f"\n{O}{t('press_enter')}{R}")
                continue
            if len(pin) != 4 or not pin.isdigit():
                print(f"\n{E}{t('pin_length_error')}{R}")
                pin = None
                input(f"\n{O}{t('press_enter')}{R}")

        with AnimacionSpinner(t('registering_user'), show_completion_message=False, min_duration=1):
            response = api_client.registrar(username, password, pin)

        if not response or response.status_code != 201:
            print_api_error(response, t('registration_error'))
            input(f"\n{O}{t('press_enter')}{R}")
            return

        reg_data = response.json()
        print(f"\n{S}{t('account_registration_successful')}{R}")

        key_password = None
        while not key_password:
            clear_screen()
            print_title("private_key_password_title")
            print(f"{I}{t('private_key_password_info1')}{R}")
            print(f"{I}{t('private_key_password_info2')}{R}")
            key_password = getpass.getpass(f"{I}» {t('key_password')}: {R}")
            key_password2 = getpass.getpass(f"{I}» {t('confirm_key_password')}: {R}")
            if key_password != key_password2:
                print(f"\n{E}{t('passwords_do_not_match')}{R}")
                key_password = None
                input(f"\n{O}{t('press_enter')}{R}")
                continue
            if len(key_password) < 12:
                print(f"\n{E}{t('key_password_length_error')}{R}")
                key_password = None
                input(f"\n{O}{t('press_enter')}{R}")

        if guardar_clave_privada(username, reg_data['private_key'], key_password):
            key_path = os.path.join(get_profile_dir(username), KEY_FILE_NAME)
            print(f"\n{S}{t('private_key_saved', KEY_FILE=key_path)}{R}")
        else:
            print(f"\n{E}{t('private_key_save_warning')}{R}")

        with AnimacionSpinner(t('generating_zkp_signature'), show_completion_message=False, min_duration=1):
            try:
                zk = ZKProof.new()
                signature = zk.create_signature(key_password.encode())
                commit_response = api_client.registro_commit(username, json.dumps(signature))
                if not commit_response or commit_response.status_code != 200:
                    print_api_error(commit_response, t('zkp_signature_error'))
                    print(f"\n{E}{t('zkp_account_error')}{R}")
            except Exception as e:
                print(f"\n{E}{t('zkp_generation_error', e=e)}{R}")

        print(f"\n{S}{t('registration_complete')}{R}")
        input(f"\n{O}{t('press_enter')}{R}")

    except (KeyboardInterrupt, ClientConnectionError):
        print(f"\n\n{E}» {t('operation_cancelled')}{R}")
        time.sleep(0.5)

def login(api_client, username=None):
    try:
        if not username:
            clear_screen()
            print_title("login_title")
            username = input(f"{I}» {t('user')}: {R}")
            if not username:
                return None, None, None

        with AnimacionSpinner(t('verifying_user'), min_duration=1, show_completion_message=False):
            start_response = api_client.login_start(username)
        
        if not start_response or start_response.status_code != 200:
            print_api_error(start_response, t('login_failed'))
            input(f"\n{O}{t('press_enter')}{R}")
            return None, None, None

        challenge_data = start_response.json()
        key_password = getpass.getpass(f"{I}» {t('private_key_password')}: {R}")
        
        with AnimacionSpinner(t('generating_zkp_proof'), show_completion_message=False):
            try:
                params = ZKParameters(*json.loads(challenge_data['params_dump']))
                zk = ZKProof(params)
                challenge = zk.create_challenge(key_password.encode(), uuid.UUID(challenge_data['nonce']).int)

            except Exception as e:
                print(f"{E}{t('zkp_proof_generation_error', e=e)}{R}")
                input(f"\n{O}{t('press_enter')}{R}")
                return None, None, None

        with AnimacionSpinner(t('verifying_proof'), show_completion_message=False):
            verify_response = api_client.login_verify(username, json.dumps(challenge), challenge_data['nonce'])

        if not verify_response or verify_response.status_code != 200:
            print_api_error(verify_response, t('login_error'))
            input(f"\n{O}{t('press_enter')}{R}")
            return None, None, None

        data = verify_response.json()
        private_key = cargar_clave_privada(username, key_password)
        if not private_key:
            key_path = os.path.join(get_profile_dir(username), KEY_FILE_NAME)
            print(f"{E}{t('key_load_error', KEY_FILE=key_path)}{R}")
            input(f"\n{O}{t('press_enter')}{R}")
            return None, None, None

        session_data = {
            "username": data['username'], "user_id": data['user_id'],
            "token": data['token'], "refresh_token": data['refresh_token']
        }
        save_session(username, session_data)
        api_client.set_token(session_data['token'], session_data['refresh_token'])
        
        config = load_client_config()
        config['last_user'] = username
        save_client_config(config)

        print(f"{S}{t('zkp_login_successful')}{R}")
        time.sleep(1)
        
        return data['username'], private_key, key_password

    except (KeyboardInterrupt, ClientConnectionError):
        print(f"\n\n{E}» {t('operation_cancelled')}{R}")
        time.sleep(0.5)
        return None, None, None



def buscar_workflow(api_client, username, private_key):
    """Workflow for interactive file search."""
    clear_screen()
    print_title("search_files")
    
    try:
        with AnimacionSpinner(t('loading_file_list')):
            response = api_client.obtener_todos_los_archivos() 

        if not response or response.status_code != 200:
            print_api_error(response, t('error_getting_files'))
            input(f"\n{O}{t('press_enter')}{R}")
            return

        items = response.json().get('items', [])
        archivos = [item for item in items if item['tipo'] == 'archivo']

        if not archivos:
            print(f"\n{I}{t('no_files_found')}{R}")
            input(f"\n{O}{t('press_enter')}{R}")
            return

        # Prepare the completer for prompt_toolkit
        nombres_archivos = [item['nombre'] for item in archivos]
        completer = WordCompleter(nombres_archivos, ignore_case=True)

        print(f"\n{I}{t('interactive_search_prompt')}{R}")
        nombre_seleccionado = prompt(
            f"{I}» {t('search')}: {R}",
            completer=completer,
            complete_style=CompleteStyle.MULTI_COLUMN,
            reserve_space_for_menu=5,
        )

        archivo_seleccionado = next((f for f in archivos if f['nombre'] == nombre_seleccionado), None)

        if archivo_seleccionado:
            print(f"\n{S}{t('file_selected')}: {archivo_seleccionado['nombre']}{R}")
            # A menu of actions for the selected file could be displayed here
            # (download, rename, delete, etc.)
            print(f"{O}ID: {archivo_seleccionado['id']}{R}")
            print(f"{O}{t('size')}: {bytes_a_legible(archivo_seleccionado.get('tamano'))}{R}")
            print(f"{O}{t('date')}: {archivo_seleccionado.get('fecha', '').replace('T', ' ')[:16]}{R}")
            input(f"\n{O}{t('press_enter')}{R}")
        else:
            print(f"\n{E}{t('file_not_found')}{R}")
            time.sleep(1.5)

    except (KeyboardInterrupt, ClientConnectionError):
        print(f"\n\n{E}» {t('operation_cancelled')}{R}")
        time.sleep(0.5)

def operaciones(api_client, username, p_key, key_pass):
    current_username, private_key, cached_key_password = username, p_key, key_pass
    
    while True:
        try:
            status_response = api_client.obtener_estado()
            if not status_response or status_response.status_code != 200:
                print(f"\n{E}{t('no_active_plan')}{R}")
                input(f"\n{O}{t('press_enter')}{R}")
                break
            status_info = status_response.json()

            print_user_banner(current_username, status_info)
            
            badges = {}
            response = api_client.obtener_comparticiones_pendientes()
            if response and response.status_code == 200:
                pendientes = response.json()
                count = len(pendientes)
                if count > 0:
                    badge_text = f"({count})" if count <= 99 else "(+99)"
                    badges['pending_shares'] = badge_text

            menu_options = [
                "file_browser", "upload_files", "manage_shared_files", 
                "pending_shares", "trash", "key_rotation", "audit_log", "split_key"
            ]
            print_menu("operations_menu", menu_options, exit_text_key="logout", badges=badges)

            opcion = input(f"{I}» {t('select_option')}: {R}")

            if opcion == '1': gestion_archivos(api_client, current_username, private_key)
            elif opcion == '2': subir_archivo(api_client, current_username, private_key, None)
            elif opcion == '3': gestionar_archivos_compartidos(api_client)
            elif opcion == '4': gestionar_comparticiones_pendientes(api_client)
            elif opcion == '5': gestionar_papelera(api_client)
            elif opcion == '6': private_key = rotar_claves(api_client, current_username, private_key, cached_key_password)
            elif opcion == '7': gestionar_auditoria(api_client)
            elif opcion == '8': dividir_clave_sss(private_key)
            elif opcion == '0':
                clear_session(current_username)
                print(f"\n{O}{t('logging_out_message')}{R}")
                time.sleep(1)
                break
            else:
                print(f"\n{E}{t('invalid_option')}{R}")
                time.sleep(1)
        except ClientConnectionError:
            print(f"\n{E}{t('session_closed_due_to_error')}{R}")
            input(f"\n{O}{t('press_enter')}{R}")
            break
        except KeyboardInterrupt:
            print(f"\n\n{E}» {t('operation_cancelled')}{R}")
            time.sleep(1)
            break

def gestionar_cuentas(api_client):
    try:
        clear_screen()
        print_title("manage_accounts_title")
        profiles = get_available_profiles()
        if not profiles:
            print(f"\n{I}{t('no_profiles_found')}{R}")
            input(f"\n{O}{t('press_enter')}{R}")
            return None

        print_menu("manage_accounts_menu", ["add_account", "switch_account", "logout_from_account"], exit_text_key="back")
        opcion = input(f"{I}» {t('select_option')}: {R}")

        if opcion == '1': # Añadir cuenta (esencialmente, registrarse)
            registrar(api_client)
            return None
        elif opcion == '2': # Cambiar de cuenta
            print_title("select_profile_to_switch")
            for i, profile in enumerate(profiles, 1):
                print(f"{O}{i}. {profile}{R}")
            try:
                choice = int(input(f"\n{I}» {t('select_option')}: {R}"))
                if 1 <= choice <= len(profiles):
                    selected_user = profiles[choice - 1]
                    return login(api_client, username=selected_user)
                else:
                    print(f"\n{E}{t('invalid_option')}{R}")
            except ValueError:
                print(f"\n{E}{t('invalid_option')}{R}")
        elif opcion == '3': # Cerrar sesión de una cuenta
            print_title("select_profile_to_logout")
            for i, profile in enumerate(profiles, 1):
                print(f"{O}{i}. {profile}{R}")
            try:
                choice = int(input(f"\n{I}» {t('select_option')}: {R}"))
                if 1 <= choice <= len(profiles):
                    selected_user = profiles[choice - 1]
                    clear_session(selected_user)
                    print(f"\n{S}{t('profile_logged_out', username=selected_user)}{R}")
                else:
                    print(f"\n{E}{t('invalid_option')}{R}")
            except ValueError:
                print(f"\n{E}{t('invalid_option')}{R}")
        
        input(f"\n{O}{t('press_enter')}{R}")
        return None

    except KeyboardInterrupt:
        print(f"\n\n{E}» {t('operation_cancelled')}{R}")
        time.sleep(0.5)
        return None

def gestion_archivos(api_client, current_username, private_key):
    """Launches the TUI file explorer."""
    app = FileExplorerApp(
        api_client=api_client,
        username=current_username,
        private_key=private_key
    )
    app.run()

def eliminar_archivo(api_client, archivo):
    if not archivo.get('propietario', True):
        # This logic is now handled in file_management
        return False

    clear_screen()
    print_title("delete_options_title")
    print(f"{I}» {t('file')}: {archivo['nombre']}{R}\n")

    menu_options = ["move_to_trash", "delete_permanently"]
    print_menu(None, menu_options, exit_text_key="cancel", start_index=1)
    
    opcion = input(f"{I}» {t('select_delete_option')} [1]: {R}") or "1"

    if opcion == '1':
        with AnimacionSpinner(t('deleting_file', file=archivo['nombre'])):
            response = api_client.eliminar_archivo(archivo['id'])
        
        if response and response.status_code == 200:
            print(f"\n{S}{t('file_moved_to_trash')}{R}")
            time.sleep(1.5)
            return True
        else:
            print_api_error(response, t('error_deleting_file'))
            input(f"\n{O}{t('press_enter')}{R}")
            return False

    elif opcion == '2':
        print(f"\n{E}‼ {t('are_you_sure_you_want_to_delete', file=archivo['nombre'])} ‼{R}")
        confirmacion = input(f"{I}{t('are_you_sure_delete_permanently_confirm')}{R}")
        
        if confirmacion.strip().upper() != t('delete_word'):
            print(f"\n{O}{t('operation_cancelled')}{R}")
            time.sleep(1)
            return False

        with AnimacionSpinner(t('deleting_permanently'), show_completion_message=False):
            # Step 1: Move to trash
            response_trash = api_client.eliminar_archivo(archivo['id'])

            if not response_trash or response_trash.status_code != 200:
                print_api_error(response_trash, t('error_deleting_file'))
                input(f"\n{O}{t('press_enter')}{R}")
                return False
            
            # Step 2: Permanently delete from trash
            response_perm = api_client.eliminar_permanentemente(archivo['id'])

            if not response_perm or response_perm.status_code != 200:
                print_api_error(response_perm, t('error_deleting_permanently'))
                input(f"\n{O}{t('press_enter')}{R}")
                return False

        print(f"\n{S}✓ {t('file_deleted_permanently')}{R}")
        time.sleep(1.5)
        return True
            
    elif opcion == '0':
        print(f"\n{O}{t('operation_cancelled')}{R}")
        time.sleep(1)
        return False
        
    else:
        print(f"\n{E}{t('invalid_option')}{R}")
        time.sleep(1)
        return False


def format_status(status_key):
    status_text = t(status_key.lower())
    if status_key == 'aceptado':
        return f"{S}✓ {status_text}{R}"
    elif status_key == 'pendiente':
        return f"{I}… {status_text}{R}"
    elif status_key == 'rechazado':
        return f"{E}✗ {status_text}{R}"
    else: # desconocido
        return f"{O}? {status_text}{R}"

def gestionar_archivos_compartidos(api_client):
    while True:
        clear_screen()
        print_title("shared_files_title")
        with AnimacionSpinner(t('loading_events')):
            response = api_client.obtener_mis_archivos_compartidos()

        if not response or response.status_code not in [200, 404]:
            print_api_error(response, t('error_getting_files'))
            input(f"\n{O}{t('press_enter')}{R}"); return

        archivos = response.json() if response.status_code == 200 else []
        if not archivos:
            print(f"\n{I}{t('no_shared_files')}{R}"); input(f"\n{O}{t('press_enter')}{R}"); return

        # UI Logic ...
        opcion = input(f"\n{I}» {t('option')}: {R}")
        # ... y el resto de la lógica de la función

def gestionar_accesos_archivo(api_client, archivo):
    # Logic to manage access
    pass

def gestionar_comparticiones_pendientes(api_client):
    try:
        while True:
            clear_screen()
            print_title("pending_shares_title")
            response = api_client.obtener_comparticiones_pendientes()
            if not response or response.status_code != 200:
                print_api_error(response, t('error_getting_shares'))
                input(f"\n{O}{t('press_enter')}{R}")
                return

            pendientes = response.json()
            if not pendientes:
                print(f"\n{I}{t('no_pending_shares')}{R}")
                input(f"\n{O}{t('press_enter')}{R}")
                return

            print(f"{T}{t('table_header_no'):<4} {t('from_user'):<20} {t('file_name'):<30} {t('date')}{R}")
            print(f"{T}{'─'*4} {'─'*20} {'─'*30} {'─'*20}{R}")
            for i, p in enumerate(pendientes, 1):
                print(f"{O}{i:<4} {p['de_usuario']:<20} {p['nombre_archivo']:<30} {p['fecha'].replace('T', ' ')[:16]}{R}")

            opcion = input(f"{I}» {t('accept_reject_prompt')}: {R}").lower().split()
            if not opcion or (len(opcion) == 1 and opcion[0] == '0'):
                return
            
            if len(opcion) != 2 or not opcion[1].isdigit():
                print(f"\n{E}{t('invalid_input')}{R}"); time.sleep(1); continue
            
            accion, num_str = opcion
            num = int(num_str) - 1

            if not (0 <= num < len(pendientes)):
                print(f"\n{E}{t('invalid_file_number')}{R}"); time.sleep(1); continue
            
            share_id = pendientes[num]['id']
            
            if accion in ['a', 'accept']:
                with AnimacionSpinner(t('accepting_share')):
                    res = api_client.aceptar_comparticion(share_id)
                if not res or res.status_code != 200: print_api_error(res, t('error_accepting_share'))
            elif accion in ['r', 'reject']:
                with AnimacionSpinner(t('rejecting_share')):
                    res = api_client.rechazar_comparticion(share_id)
                if not res or res.status_code != 200: print_api_error(res, t('error_rejecting_share'))
            else:
                print(f"\n{E}{t('invalid_input')}{R}"); time.sleep(1)

    except KeyboardInterrupt:
        return
    except ClientConnectionError:
        print(f"\n{E}{t('server_not_responding')}{R}")
        time.sleep(2)

def rotar_claves(api_client, current_username, private_key, cached_key_password):
    try:
        clear_screen()
        print_title("key_rotation_title")
        print(f"{E}{t('key_rotation_warning')}{R}")
        
        pin = getpass.getpass(f"{I}» {t('account_pin')}: {R}")
        if not pin:
            return private_key

        response = api_client.verificar_pin(pin)
        if not response or response.status_code != 200 or not response.json().get('verificado'):
            print(f"\n{E}{t('pins_do_not_match')}{R}")
            input(f"\n{O}{t('press_enter')}{R}")
            return private_key

        if not cached_key_password:
            print(f"\n{E}{t('cached_password_not_found')}{R}\n")
            input(f"\n{O}{t('press_enter')}{R}")
            return private_key

        clave_privada_actual = private_key
        
        with AnimacionSpinner(t('rotating_security_keys'), show_completion_message=False):
            response = api_client.rotar_claves(clave_privada_actual)

        if response is None:
            print(f"{E}{t('server_unavailable')}{R}")
            input(f"\n{O}{t('press_enter')}{R}")
            return private_key

        if response.status_code == 200:
            data = response.json()
            print(f"{S}✓ {t('keys_rotated_successfully')}!{R}")
            print(f"{S}✓ {t('new_public_key_saved_on_server')}{R}")
            
            if guardar_clave_privada(current_username, data['private_key'], cached_key_password):
                key_path = os.path.join(get_profile_dir(current_username), KEY_FILE_NAME)
                print(f"{S}✓ {t('new_private_key_saved', KEY_FILE=key_path)}{R}")
                private_key = data['private_key']
            else:
                print(f"{E}{t('warning_could_not_save_new_private_key')}{R}")
                print(f"{O}{t('save_key_manually')}:{R}")
                print(data['private_key'])
        else:
            print_api_error(response, t('error_rotating_keys'))
        input(f"\n{O}{t('press_enter')}{R}")
        return private_key
    except (KeyboardInterrupt, ClientConnectionError):
        print(f"\n\n{E}» {t('operation_cancelled')}{R}")
        time.sleep(0.5)
        return private_key

def gestionar_auditoria(api_client):
    try:
        pagina_actual = 1
        while True:
            clear_screen()
            print_title(f"{t('audit_log_title')} - {t('page')} {pagina_actual}")
            with AnimacionSpinner(t('loading_events')):
                response = api_client.obtener_auditoria(pagina_actual)
            
            if not response or response.status_code != 200:
                print_api_error(response, t('error_getting_audit_log')); break

            data = response.json()
            eventos = data.get('eventos', [])
            if not eventos:
                print(f"\n{I}{t('no_audit_events')}{R}"); break

            for evento in eventos:
                fecha = evento.get('fecha', 'N/A').replace('T', ' ')[:19]
                detalle = evento.get('detalle', 'N/A')
                ip = evento.get('ip', 'N/A')
                print(f"{O}[{fecha}] {evento.get('evento', 'N/A')}: {detalle} (IP: {ip}){R}")

            if not data.get('has_next'):
                print(f"\n{I}{t('end_of_audit_log')}{R}"); break
            
            opcion = input(f"\n{O}{t('press_enter_for_next_page')}: {R}")
            if opcion.lower() == 's': break
            pagina_actual += 1
    except (KeyboardInterrupt, ClientConnectionError):
        print(f"\n\n{E}» {t('operation_cancelled')}{R}")
        time.sleep(0.5)
    
    input(f"\n{O}{t('press_enter')}{R}")

def gestionar_papelera(api_client):
    """Manages trash bin operations."""
    while True:
        try:
            clear_screen()
            print_title("trash_title")

            with AnimacionSpinner(t('loading_trash_items')):
                response = api_client.obtener_papelera()

            if not response or response.status_code != 200:
                print_api_error(response, t('error_loading_trash'))
                input(f"\n{O}{t('press_enter')}{R}")
                return

            items = response.json()

            print(f"\n{T}{t('table_header_id'):<6} {t('item_name'):<35} {t('table_header_size'):<12} {t('deletion_date')}{R}")
            print(f"{T}{'─'*6} {'─'*35} {'─'*12} {'─'*20}{R}")

            if not items:
                print(f"{I}{' ' * 25}{t('trash_is_empty')}{R}")

            for item in items:
                nombre = item['nombre']
                if len(nombre) > 33:
                    nombre = nombre[:30] + "..."
                
                tamano = bytes_a_legible(item.get('tamano')) if item.get('tamano') is not None else ''
                fecha = item.get('fecha_eliminacion', '').replace('T', ' ')[:16]
                
                print(f"{O}{item['id']:<6} {nombre:<35} {tamano:<12} {fecha}{R}")

            trash_options_text = t('trash_options').upper()
            print(f"\n{T}{trash_options_text}{R}")

            opcion_str = input(f"{I}» {t('select_item_or_option')}: {R}")
            opcion = opcion_str.lower().split()
            
            cmd = opcion[0] if opcion else ''
            
            if cmd == 'q': break
            
            if cmd in ['r', 'e']:
                item_id = -1
                if len(opcion) > 1 and opcion[1].isdigit():
                    item_id = int(opcion[1])
                else:
                    try:
                        num_str = input(t('item_id_prompt', cmd=cmd))
                        if num_str.isdigit(): item_id = int(num_str)
                    except (ValueError, KeyboardInterrupt): continue
                
                if item_id == -1 or not any(item['id'] == item_id for item in items):
                    print(f"\n{E}{t('invalid_file_id')}{R}"); time.sleep(1); continue

                if cmd == 'r':
                    with AnimacionSpinner(t('restoring_file')):
                        res = api_client.restaurar_archivo(item_id)
                    if res and res.status_code == 200:
                        print(f"\n{S}✓ {t('file_restored_successfully')}{R}")
                    else:
                        print_api_error(res, t('error_restoring_file'))
                    time.sleep(2)

                elif cmd == 'e':
                    confirm = input(f"{I}{t('are_you_sure_delete_permanently')} {R}").lower()
                    if confirm.startswith('s') or confirm.startswith('y'):
                        with AnimacionSpinner(t('deleting_permanently')):
                            res = api_client.eliminar_permanentemente(item_id)
                        if res and res.status_code == 200:
                            print(f"\n{S}✓ {t('file_deleted_permanently')}{R}")
                        else:
                            print_api_error(res, t('error_deleting_permanently'))
                        time.sleep(2)

        except KeyboardInterrupt:
            break
        except (ClientConnectionError, requests.exceptions.RequestException):
            print(f"\n{E}{t('server_not_responding')}{R}"); time.sleep(2); break