# -*- coding: utf-8 -*-
import os
import sys
import uuid
import time
import base64
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

from .ui import (
    clear_screen, print_title, print_menu, print_progress_bar, 
    AnimacionSpinner, t, I, S, E, R, O, print_api_error
)
from .crypto import calcular_hash_archivo, firmar_hash, descifrar_clave_aes, descifrar_archivo_fernet
from .state_manager import (
    cargar_estado_subida, guardar_estado_subida, limpiar_estado_subida,
    cargar_estado_descarga, guardar_estado_descarga, limpiar_estado_descarga
)
from .config import TEMP_DIR
from .api_client import ClientConnectionError

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend


try:
    import tkinter as tk
    from tkinter import filedialog
    HAS_TKINTER = True
except ImportError:
    HAS_TKINTER = False

try:
    import readline
    HAS_READLINE = True
except ImportError:
    HAS_READLINE = False

def path_completer(text, state):
    matches = []
    expanded_text = os.path.expanduser(text)
    dir_name = os.path.dirname(expanded_text)
    base_name = os.path.basename(expanded_text)
    if not os.path.exists(dir_name):
        return None
    for f in os.listdir(dir_name):
        if f.startswith(base_name):
            full_path = os.path.join(dir_name, f)
            if os.path.isdir(full_path):
                matches.append(full_path + '/')
            else:
                matches.append(full_path)
    if state < len(matches):
        return matches[state]
    return None

def seleccionar_ruta_grafico(tipo='archivo'):
    if not HAS_TKINTER:
        print(f"{E}{t('tkinter_not_available')}{R}")
        return None
    root = tk.Tk()
    root.withdraw()
    if tipo == 'archivo':
        path = filedialog.askopenfilename(title=t('select_file_to_upload'))
    else:
        path = filedialog.askdirectory(title=t('select_folder_to_upload'))
    root.destroy()
    return path

def seleccionar_ruta_manual():
    if HAS_READLINE:
        readline.set_completer_delims(" \t\n;")
        readline.set_completer(path_completer)
        readline.parse_and_bind("tab: complete")
    print(f"\n{I}{t('file_path_prompt')}{R}")
    path = input("> ")
    if HAS_READLINE:
        readline.set_completer(None)
    if not path:
        return None
    path = os.path.expanduser(path)
    if not os.path.exists(path):
        print(t('file_not_found_try_again'))
        return seleccionar_ruta_manual()
    return path

def _monitorear_procesamiento(api_client, task_id, nombre_archivo):
    """
    Sondea el estado de una tarea de Celery y muestra una barra de progreso.
    """
    while True:
        try:
            response = api_client.obtener_estado_tarea(task_id)
            if not response or response.status_code != 200:
                # Si la API falla (ej. 429), lo indicamos y reintentamos
                error_msg = response.json().get('error', 'Error de conexión') if response else 'Error de conexión'
                sys.stdout.write(f"\r{E}Error API: {error_msg}. Reintentando...{' ' * 20}{R}")
                sys.stdout.flush()
                time.sleep(5) # Espera más tiempo si hay un error de API
                continue

            data = response.json()
            state = data.get('state')
            info = data.get('info', {})
            
            if state == 'SUCCESS':
                # Barra de progreso final al 100%
                print_progress_bar(100, 100, prefix=f"{S}✓ {nombre_archivo}:", suffix=t('completed'), length=50)
                return True
            elif state == 'FAILURE':
                sys.stdout.write(f"\r{E}✗ {t('file_processing_failed', file=nombre_archivo)}{' ' * 50}{R}\n")
                return False

            status = info.get('status', t('processing_pending'))
            progress = info.get('progress', 0)
            
            print_progress_bar(progress, 100, prefix=f"{I}  {nombre_archivo}:", suffix=status, length=50)

            time.sleep(1)

        except (ClientConnectionError, requests.exceptions.RequestException):
            sys.stdout.write(f"\r{E}{t('connection_lost_retrying')}{' ' * 20}{R}")
            sys.stdout.flush()
            time.sleep(5)
        except KeyboardInterrupt:
            sys.stdout.write(f"\n{E}{t('monitoring_cancelled_by_user')}{R}\n")
            return False




def _subir_un_solo_archivo(api_client, current_username, private_key, current_folder_id, archivo_path, progress_callback=None):
    """
    Lógica para subir un único archivo.
    Retorna el task_id si la subida se inicia correctamente, None en caso contrario.
    """
    nombre_real = os.path.basename(archivo_path)
    if progress_callback:
        progress_callback(nombre_real, 'calculating_hash')

    sha256_hash = calcular_hash_archivo(archivo_path)
    file_hash_hex = sha256_hash.hexdigest()
    file_hash_bytes = sha256_hash.digest()

    try:
        firma = firmar_hash(file_hash_bytes, private_key)
    except Exception as e:
        print(f"\n{E}{t('error_signing_file')}: {str(e)}{R}")
        return None

    upload_id = cargar_estado_subida(current_username, file_hash_hex)
    uploaded_chunks = set()
    tamano_total = os.path.getsize(archivo_path)

    if upload_id:
        if progress_callback:
            progress_callback(nombre_real, 'resuming')
        response = api_client.estado_subida(upload_id)
        if response and response.status_code == 200:
            upload_data = response.json()
            chunk_size = upload_data['chunk_size']
            uploaded_chunks = set(upload_data.get('uploaded_chunks', []))
        else:
            upload_id = None
    
    if not upload_id:
        if progress_callback:
            progress_callback(nombre_real, 'initiating')
        
        response = api_client.iniciar_subida(nombre_real, tamano_total, file_hash_hex, firma, current_folder_id)
        if not response or response.status_code != 201:
            print_api_error(response, f"{t('could_not_initiate_upload')} ({nombre_real})")
            return None
        
        upload_data = response.json()
        upload_id = upload_data['upload_id']
        chunk_size = upload_data['chunk_size']
        guardar_estado_subida(current_username, file_hash_hex, upload_id)

    total_chunks = (tamano_total + chunk_size - 1) // chunk_size
    try:
        with open(archivo_path, 'rb') as f:
            for i in range(total_chunks):
                if i in uploaded_chunks:
                    continue
                
                f.seek(chunk_size * i)
                chunk_data = f.read(chunk_size)
                if not chunk_data:
                    break

                chunk_response = api_client.subir_chunk(upload_id, i, chunk_data)
                if not chunk_response or chunk_response.status_code != 200:
                    raise Exception(t('chunk_upload_failed'))
                
                uploaded_chunks.add(i)
                if progress_callback:
                    progress_callback(nombre_real, 'uploading', len(uploaded_chunks), total_chunks)

    except Exception as e:
        print(f"\n{E}{t('upload_interrupted')} ({nombre_real}): {e}{R}")
        return None

    if progress_callback:
        progress_callback(nombre_real, 'completing')
    
    complete_response = api_client.completar_subida(upload_id)

    if not complete_response or complete_response.status_code not in [201, 202]:
        print_api_error(complete_response, f"{t('error_completing_upload')} ({nombre_real})")
        return None
    else:
        limpiar_estado_subida(current_username, file_hash_hex)
        if progress_callback:
            progress_callback(nombre_real, 'done')
        
        # Devolver el ID de la tarea para el monitoreo
        return complete_response.json().get('task_id')

def subir_archivo(api_client, current_username, private_key, current_folder_id):
    clear_screen()
    print_title("upload_file_title")

    print_menu("selection_method", ["upload_file", "upload_folder"], exit_text_key="cancel")
    opcion = input(f"{I}» {t('option')}: {R}")
    
    ruta_seleccionada = None
    es_directorio = False
    if opcion == "1":
        ruta_seleccionada = seleccionar_ruta_grafico('archivo') or seleccionar_ruta_manual()
    elif opcion == "2":
        ruta_seleccionada = seleccionar_ruta_grafico('directorio') or seleccionar_ruta_manual()
        es_directorio = True
    else:
        return

    if not ruta_seleccionada or not os.path.exists(ruta_seleccionada):
        print(f"{E}{t('file_not_selected_or_exists')}{R}")
        input(f"\n{O}{t('press_enter')}{R}")
        return

    archivos_a_subir = []
    if es_directorio and os.path.isdir(ruta_seleccionada):
        for dirpath, _, filenames in os.walk(ruta_seleccionada):
            for f in filenames:
                archivos_a_subir.append(os.path.join(dirpath, f))
    elif os.path.isfile(ruta_seleccionada):
        archivos_a_subir.append(ruta_seleccionada)
    else:
        print(f"{E}{t('invalid_path')}{R}")
        input(f"\n{O}{t('press_enter')}{R}")
        return

    if not archivos_a_subir:
        print(f"{I}{t('no_files_to_upload')}{R}")
        input(f"\n{O}{t('press_enter')}{R}")
        return

    max_workers = 4
    uploads_exitosas = 0
    uploads_fallidas = 0
    
    print(f"\n{I}{t('starting_upload_of_n_files', n=len(archivos_a_subir))} {t('using_n_threads', n=max_workers)}...{R}")
    
    # Usaremos una lista para mantener el orden y los resultados
    resultados = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_path = {
            executor.submit(
                _subir_un_solo_archivo, 
                api_client, current_username, private_key, current_folder_id, path
            ): path for path in archivos_a_subir
        }

        for future in as_completed(future_to_path):
            path = future_to_path[future]
            nombre_archivo = os.path.basename(path)
            task_id = None
            try:
                task_id = future.result()
                if task_id:
                    print(f"{S}✓ {t('file_uploaded_successfully', file=nombre_archivo)}{R}")
                else:
                    # El error ya se imprimió dentro de _subir_un_solo_archivo
                    uploads_fallidas += 1
            except Exception as exc:
                print(f"{E}✗ {t('file_upload_generated_exception', file=nombre_archivo, exc=exc)}{R}")
                uploads_fallidas += 1
            
            resultados.append({'nombre': nombre_archivo, 'task_id': task_id})
            print(f"{I}{t('upload_summary', done=len(resultados), total=len(archivos_a_subir))}")

    print(f"\n{S}{t('upload_phase_finished')}{R}")
    print(f"─" * 40)
    print(f"{I}{t('processing_phase_started')}{R}\n")

    for resultado in resultados:
        if resultado['task_id']:
            if _monitorear_procesamiento(api_client, resultado['task_id'], resultado['nombre']):
                uploads_exitosas += 1
            else:
                uploads_fallidas += 1
    
    print(f"\n{S}{t('upload_process_finished')}{R}")
    print(f"{S}{t('successful_uploads')}: {uploads_exitosas}{R}")
    print(f"{E}{t('failed_uploads')}: {uploads_fallidas}{R}")
    input(f"\n{O}{t('press_enter')}{R}")


def _descargar_un_solo_archivo(api_client, current_username, private_key, archivo, save_path):
    """
    Lógica para descargar y descifrar un único archivo. No interactúa con el usuario.
    Retorna True si la descarga es exitosa, False en caso contrario.
    """
    temp_path = cargar_estado_descarga(current_username, archivo['id'])
    if temp_path and os.path.exists(temp_path):
        downloaded_size = os.path.getsize(temp_path)
    else:
        temp_dir = os.path.join(TEMP_DIR, f"dl_{uuid.uuid4().hex}")
        os.makedirs(temp_dir, exist_ok=True)
        temp_path = os.path.join(temp_dir, archivo['nombre'])
        downloaded_size = 0
        guardar_estado_descarga(current_username, archivo['id'], temp_path)

    total_size = archivo['tamano']
    try:
        with open(temp_path, 'ab') as f:
            while downloaded_size < total_size:
                range_header = f'bytes={downloaded_size}-'
                response = api_client.descargar_chunk(archivo['id'], range_header=range_header)

                if not response or response.status_code not in [200, 206]:
                    # No imprimir error aquí, solo lanzar excepción para que el gestor concurrente lo maneje
                    raise Exception(t('chunk_download_failed'))

                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded_size += len(chunk)
    except Exception:
        # El error se registrará en el gestor concurrente
        return False

    response_clave = api_client.obtener_clave_archivo(archivo['id'])
    if not response_clave or response_clave.status_code != 200:
        os.remove(temp_path)
        limpiar_estado_descarga(current_username, archivo['id'])
        return False

    try:
        clave_cifrada_b64 = response_clave.json()['clave_cifrada']
        clave_fernet = descifrar_clave_aes(clave_cifrada_b64, private_key)
    except Exception:
        os.remove(temp_path)
        limpiar_estado_descarga(current_username, archivo['id'])
        return False

    descifrado_exitoso = descifrar_archivo_fernet(temp_path, save_path, clave_fernet)

    if descifrado_exitoso:
        limpiar_estado_descarga(current_username, archivo['id'])
        os.remove(temp_path)
        return True
    else:
        return False

def descargar_archivo(api_client, current_username, private_key, archivo):
    clear_screen()
    print_title("download_file_title")
    print(f"{I}» {t('file')}: {archivo['nombre']}{R}")
    save_path = input(f"{I}» {t('save_path_prompt')}: {R}") or archivo['nombre']
    
    print(f"\n{I}» {t('initiating_download')}…{R}")
    with AnimacionSpinner(t('downloading'), show_completion_message=False):
        exito = _descargar_un_solo_archivo(api_client, current_username, private_key, archivo, save_path)

    if exito:
        print(f"\n{S}✓ {t('file_downloaded_and_decrypted_to', path=save_path)}{R}")
    else:
        print(f"\n{E}✗ {t('download_failed')}{R}")
    
    input(f"\n{O}{t('press_enter')}{R}")

def descargar_archivos_concurrentemente(api_client, current_username, private_key, archivos, save_dir):
    max_workers = 4
    descargas_exitosas = 0
    descargas_fallidas = 0
    
    print(f"\n{I}{t('starting_download_of_n_files', n=len(archivos))} {t('using_n_threads', n=max_workers)}...{R}")
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_archivo = {
            executor.submit(
                _descargar_un_solo_archivo, 
                api_client, current_username, private_key, archivo, os.path.join(save_dir, archivo['nombre'])
            ): archivo for archivo in archivos
        }

        for future in as_completed(future_to_archivo):
            archivo = future_to_archivo[future]
            nombre_archivo = archivo['nombre']
            try:
                if future.result():
                    print(f"{S}✓ {t('file_downloaded_successfully', file=nombre_archivo)}{R}")
                    descargas_exitosas += 1
                else:
                    print(f"{E}✗ {t('file_download_failed', file=nombre_archivo)}{R}")
                    descargas_fallidas += 1
            except Exception as exc:
                print(f"{E}✗ {t('file_download_generated_exception', file=nombre_archivo, exc=exc)}{R}")
                descargas_fallidas += 1
            
            print(f"{I}{t('download_summary', done=descargas_exitosas + descargas_fallidas, total=len(archivos))}")

    print(f"\n{S}{t('download_process_finished')}{R}")
    print(f"{S}{t('successful_downloads')}: {descargas_exitosas}{R}")
    print(f"{E}{t('failed_downloads')}: {descargas_fallidas}{R}")
    input(f"\n{O}{t('press_enter')}{R}")


def compartir_archivo(api_client, private_key, archivo):
    try:
        clear_screen()
        print_title("share_file_title")
        print(f"{I}» {t('file')}: {archivo['nombre']}{R}")
        
        username_dest = input(f"{I}» {t('user_id_to_share_with')}: {R}")
        if not username_dest:
            return

        with AnimacionSpinner(t('verifying_user'), show_completion_message=False):
            response_pk = api_client.obtener_clave_publica(username_dest)
        
        if not response_pk or response_pk.status_code != 200:
            if response_pk and response_pk.status_code == 404:
                print(f"\n{E}{t('user_unavailable')}{R}")
            else:
                print_api_error(response_pk, "Error obteniendo la clave pública del destinatario")
            input(f"\n{O}{t('press_enter')}{R}")
            return

        dest_data = response_pk.json()
        public_key_dest_pem = dest_data['public_key']
        usuario_id_destino = dest_data['user_id']

        with AnimacionSpinner("Obteniendo clave de archivo...", show_completion_message=False):
            response_clave_propia = api_client.obtener_clave_archivo(archivo['id'])

        if not response_clave_propia or response_clave_propia.status_code != 200:
            print_api_error(response_clave_propia, "No se pudo obtener la clave del archivo")
            input(f"\n{O}{t('press_enter')}{R}")
            return

        clave_cifrada_b64 = response_clave_propia.json()['clave_cifrada']

        try:
            clave_archivo_plana = descifrar_clave_aes(clave_cifrada_b64, private_key)
            public_key_dest = serialization.load_pem_public_key(
                public_key_dest_pem.encode(),
                backend=default_backend()
            )
            
            clave_cifrada_para_dest_bytes = public_key_dest.encrypt(
                clave_archivo_plana,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            clave_cifrada_para_dest_b64 = base64.b64encode(clave_cifrada_para_dest_bytes).decode()

        except Exception as e:
            print(f"\n{E}Error en la operación criptográfica local: {e}{R}")
            input(f"\n{O}{t('press_enter')}{R}")
            return

        with AnimacionSpinner(t('sharing_file', file=archivo['nombre']), show_completion_message=False):
            response_final = api_client.compartir_archivo(archivo['id'], usuario_id_destino, clave_cifrada_para_dest_b64)

        if response_final and response_final.status_code == 201:
            print(f"{S}✓ {t('file_shared_successfully')}!{R}")
        else:
            print_api_error(response_final, t('error_sharing_file'))
        
        input(f"\n{O}{t('press_enter')}{R}")

    except (ClientConnectionError, requests.exceptions.RequestException):
        print(f"\n{E}{t('server_not_responding')}{R}")
        input(f"\n{O}{t('press_enter')}{R}")
    except KeyboardInterrupt:
        print(f"\n\n{E}» {t('operation_cancelled')}{R}")
        time.sleep(0.5)
