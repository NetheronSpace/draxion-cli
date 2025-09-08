# -*- coding: utf-8 -*-
import os
import sys
import time
import click

# Add the src directory to the path to import modules
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(current_dir, 'src'))

from src.ui import clear_screen, print_menu, t, I, E, R, O
from src.config import load_client_config
from src.i18n import set_language
from src.api_client import APIClient, ClientConnectionError
from src.workflows import registrar, login as workflow_login, operaciones, gestionar_cuentas
from src.sss import recuperar_clave_sss

# --- Initial Setup ---
config = load_client_config()
set_language(config.get('language', 'es'))
api_client = APIClient()

@click.group()
def cajanegra():
    """
    Draxion: A secure cloud storage CLI client.
    """
    pass

@cajanegra.command()
def login():
    """Logs into your Draxion account."""
    try:
        username, private_key, key_pass = workflow_login(api_client)
        if username and private_key:
            operaciones(api_client, username, private_key, key_pass)
    except ClientConnectionError:
        click.echo(f"\n{E}{t('session_closed_due_to_error')}{R}")
    except KeyboardInterrupt:
        click.echo(f"\n\n{E}» {t('operation_cancelled')}{R}")

@cajanegra.command()
def register():
    """Registers a new account in Draxion."""
    try:
        registrar(api_client)
    except ClientConnectionError:
        click.echo(f"\n{E}{t('session_closed_due_to_error')}{R}")
    except KeyboardInterrupt:
        click.echo(f"\n\n{E}» {t('operation_cancelled')}{R}")

@cajanegra.command(name='recover-key')
def recover_key():
    """Recovers your private key using the shared secret."""
    recuperar_clave_sss()

@cajanegra.command(name='manage-accounts')
def manage_accounts():
    """Manages saved user profiles."""
    try:
        login_result = gestionar_cuentas(api_client)
        if login_result:
            username, private_key, key_pass = login_result
            if username and private_key:
                operaciones(api_client, username, private_key, key_pass)
    except ClientConnectionError:
        click.echo(f"\n{E}{t('session_closed_due_to_error')}{R}")
    except KeyboardInterrupt:
        click.echo(f"\n\n{E}» {t('operation_cancelled')}{R}")

@cajanegra.command(name='change-language')
def change_language():
    """Changes the interface language (en/es)."""
    clear_screen()
    print_menu("language_menu_title", ["English", "Español"], exit_text_key="back")
    opcion = click.prompt(f"{I}» {t('select_option')}", type=click.Choice(['1', '2', '0']), show_choices=False)
    
    if opcion == '1':
        set_language('en')
        click.echo(f"\n{O}{t('language_changed')}{R}")
    elif opcion == '2':
        set_language('es')
        click.echo(f"\n{O}{t('language_changed')}{R}")
    else:
        return
    time.sleep(1)

if __name__ == "__main__":
    cajanegra()
