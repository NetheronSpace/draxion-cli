# -*- coding: utf-8 -*-
import base64
import json
import getpass
import time
import os

import shamirs
from shamirs import share as Share

from .ui import clear_screen, print_title, t, I, S, E, R, O, T, WIDTH
from .crypto import guardar_clave_privada
from .config import get_profile_dir, KEY_FILE_NAME

def dividir_clave_sss(private_key):
    """Divide la clave privada en fragmentos usando SSS."""
    if not private_key:
        print(f"\n{E}{t('must_be_logged_in_to_split_key')}{R}")
        input(f"\n{O}{t('press_enter')}{R}")
        return

    clear_screen()
    print_title("split_key_title")
    print(f"{I}{t('split_key_info1')}{R}")
    print(f"{I}{t('split_key_info2')}{R}")
    print(f"{E}{t('split_key_warning')}{R}\n")

    try:
        n = int(input(f"{I}» {t('total_shares_prompt')}: {R}"))
        k = int(input(f"{I}» {t('required_shares_prompt')}: {R}"))
        if k > n:
            print(f"\n{E}{t('k_greater_than_n_error')}{R}")
            input(f"\n{O}{t('press_enter')}{R}")
            return
    except ValueError:
        print(f"\n{E}{t('invalid_number_error')}{R}")
        input(f"\n{O}{t('press_enter')}{R}")
        return

    print(f"\n{I}» {t('generating_n_shares', n=n)}...{R}")
    try:
        secret_bytes = private_key.encode('utf-8')
        chunk_size = 15  # Tamaño de chunk para SSS
        chunks = [secret_bytes[i:i+chunk_size] for i in range(0, len(secret_bytes), chunk_size)]
        
        all_shares = [[] for _ in range(n)]

        for chunk in chunks:
            chunk_int = int.from_bytes(chunk, 'big')
            chunk_shares_list = list(shamirs.shares(chunk_int, quantity=n, threshold=k))
            for i in range(n):
                share = chunk_shares_list[i]
                all_shares[i].append([share.index, share.value])
        
        final_shares_str = []
        for i in range(n):
            share_data = json.dumps(all_shares[i])
            share_str = base64.b64encode(share_data.encode('utf-8')).decode('utf-8')
            final_shares_str.append(share_str)

    except Exception as e:
        print(f"\n{E}{t('error_splitting_key')}: {str(e)}{R}")
        input(f"\n{O}{t('press_enter')}{R}")
        return

    print(f"{S}{t('key_split_successfully')}{R}")
    
    for i, share_str in enumerate(final_shares_str, 1):
        print(f"\n{T}--- {t('share')} {i} de {n} ---")
        print(f"{O}{share_str}{R}")
        print(f"{T}{'-' * WIDTH}{R}")

    print(f"\n{t('save_shares_prompt')}{R}")
    input(f"\n{O}» {t('press_enter_to_return')}")

def recuperar_clave_sss():
    """Recupera una clave privada a partir de fragmentos SSS."""
    clear_screen()
    print_title("recover_key_title")

    username = input(f"{I}» {t('user')}: {R}")
    if not username:
        return

    profile_dir = get_profile_dir(username)
    key_path = os.path.join(profile_dir, KEY_FILE_NAME)

    if os.path.exists(key_path):
        confirm = input(f"{I}{t('key_file_exists_warning', KEY_FILE=key_path)} (s/n): {R}").lower()
        if confirm != 's':
            return

    print(f"{I}{t('enter_shares_prompt')}{R}\n")
    
    collected_shares = []
    while True:
        print(f"{I}» {t('share')} {len(collected_shares) + 1}: {R}", end="")
        share_str = input()
        if not share_str:
            break
        try:
            share_data = base64.b64decode(share_str).decode('utf-8')
            share_chunks = json.loads(share_data)
            collected_shares.append([Share(index=chunk[0], value=chunk[1]) for chunk in share_chunks])
            print(f"{S}✓ {t('share_accepted')}{R}")
        except (ValueError, TypeError, IndexError, json.JSONDecodeError):
            print(f"\n{E}Fragmento inválido o corrupto. Inténtalo de nuevo.{R}")
            continue

    if not collected_shares:
        return

    print(f"\n{I}» {t('recovering_key_with_n_shares', n=len(collected_shares))}...{R}")
    try:
        num_chunks = len(collected_shares[0])
        recovered_bytes = b''

        for i in range(num_chunks):
            chunk_shares_to_recover = [share[i] for share in collected_shares]
            recovered_int = shamirs.interpolate(chunk_shares_to_recover)
            byte_len = (recovered_int.bit_length() + 7) // 8
            recovered_bytes += recovered_int.to_bytes(byte_len, 'big')
        
        recovered_private_key = recovered_bytes.decode('utf-8')

    except Exception as e:
        print(f"\n{E}{t('error_recovering_key')}: {str(e)}{R}")
        input(f"\n{O}{t('press_enter')}{R}")
        return

    print(f"{S}{t('key_recovered_successfully')}{R}")

    print(f"{I}{t('create_new_password_for_key')}{R}")
    new_key_password = None
    while not new_key_password:
        new_key_password = getpass.getpass(f"{I}» {t('new_key_password')}: {R}")
        new_key_password2 = getpass.getpass(f"{I}» {t('confirm_new_key_password')}: {R}")
        if new_key_password != new_key_password2:
            print(f"{E}{t('passwords_do_not_match')}{R}")
            new_key_password = None
            continue
        if len(new_key_password) < 12:
            print(f"{E}{t('key_password_length_error')}{R}")
            new_key_password = None

    if guardar_clave_privada(username, recovered_private_key, new_key_password):
        print(f"{S}{t('new_private_key_saved', KEY_FILE=key_path)}{R}")
        print(f"{I}{t('you_can_login_now')}{R}")
    else:
        print(f"{E}{t('critical_error_saving_key')}{R}")
        print(f"{O}{t('save_key_manually')}:{R}")
        print(recovered_private_key)

    input(f"\n{O}{t('press_enter')}{R}")
