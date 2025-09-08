# -*- coding: utf-8 -*-
import os
import sys
import threading
import itertools
import time
import re
import json
from .i18n import t

# --- Colores y Estilos ---
T = "\033[1;36m"  # Turquesa para bordes y títulos
O = "\033[97m"  # Blanco para opciones
I = "\033[93m"  # Amarillo para información y prompts
S = "\033[92m"  # Verde para éxito
E = "\033[91m"  # Rojo para errores
R = "\033[0m"   # Reset
WIDTH = 65

def get_visual_length(text):
    """Calcula la longitud visual del texto, ignorando secuencias de escape ANSI y ajustando para emojis anchos."""
    clean_text = re.sub(r'\x1B\[[0-?]*[ -/]*[@-~]', '', text)
    adjustment = 0
    wide_emojis = "🔑📂📁📤🔗🔄📝👤📬🌐👥"
    for char in clean_text:
        if char in wide_emojis:
            adjustment += 1
    return len(clean_text) + adjustment

def bytes_a_legible(b):
    """Convierte un tamaño en bytes a un formato legible (MB o GB)."""
    if b is None: b = 0
    gb = b / (1024**3)
    mb = b / (1024**2)
    if gb >= 1:
        return f"{gb:.2f} GB"
    else:
        return f"{mb:.2f} MB"

def clear_screen():
    """Limpia la pantalla de la consola."""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_title(title_key):
    """Imprime un título de sección con formato."""
    title = t(title_key)
    border = "═" * (WIDTH - 2)
    padding = WIDTH - 2 - get_visual_length(title)
    left_pad = padding // 2
    right_pad = padding - left_pad
    print(f"\n{T}╔{border}╗{R}")
    print(f"{T}║{' ' * left_pad}{title}{' ' * right_pad}║{R}")
    print(f"{T}╚{border}╝{R}")

def print_menu(title_key, options_keys, exit_text_key=None, badges=None, start_index=1):
    """Imprime un menú de opciones con formato."""
    if title_key:
        title = t(title_key)
        border = "─" * (WIDTH - 2)
        title_padding = WIDTH - 2 - get_visual_length(title)
        left_pad = title_padding // 2
        right_pad = title_padding - left_pad
        print(f"\n{T}┌{border}┐{R}")
        print(f"{T}│{' ' * left_pad}{title}{' ' * right_pad}│{R}")
        print(f"{T}├{border}┤{R}")

    for i, option_key in enumerate(options_keys, start=start_index):
        option_text = f"{i}. {t(option_key)}"
        if badges and option_key in badges:
            badge = badges[option_key]
            option_text += f" {I}{badge}{O}"

        padding = WIDTH - get_visual_length(option_text) - 4
        if padding < 0: padding = 0
        padded_option = option_text + " " * padding
        print(f"{T}│ {O}{padded_option} {T}│{R}")

    if exit_text_key:
        if title_key: # Solo imprimir separador si había título
            print(f"{T}├{border}┤{R}")
        exit_option = f"0. {t(exit_text_key)}"
        padding = WIDTH - get_visual_length(exit_option) - 4
        if padding < 0: padding = 0
        padded_exit = exit_option + " " * padding
        print(f"{T}│ {O}{padded_exit} {T}│{R}")
    
    if title_key:
        print(f"{T}└{border}┘{R}")

class AnimacionSpinner:
    """Gestiona una animación de spinner en la consola para operaciones largas."""
    def __init__(self, mensaje="Procesando...", show_completion_message=True, min_duration=0):
        self._mensaje = mensaje.rstrip('.')
        self.show_completion_message = show_completion_message
        self.min_duration = min_duration
        self.evento_detener = threading.Event()
        self.animacion = itertools.cycle(['.  ', '.. ', '...'])
        self.hilo = threading.Thread(target=self._girar)

    @property
    def mensaje(self):
        return self._mensaje

    @mensaje.setter
    def mensaje(self, value):
        self._mensaje = value.rstrip('.')

    def _girar(self):
        while not self.evento_detener.is_set():
            clear_line = ' ' * (get_visual_length(self._mensaje) + 20)
            sys.stdout.write(f'\r{clear_line}\r')
            sys.stdout.write(f'\r{T}» {self._mensaje}{next(self.animacion)}{R}')
            sys.stdout.flush()
            time.sleep(0.2)

    def __enter__(self):
        self.start_time = time.time()
        self.hilo.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        elapsed = time.time() - self.start_time
        if elapsed < self.min_duration:
            time.sleep(self.min_duration - elapsed)
        
        self.evento_detener.set()
        self.hilo.join()
        time.sleep(0.5) 
        clear_line = ' ' * (get_visual_length(self._mensaje) + 20)
        sys.stdout.write(f'\r{clear_line}\r')
        sys.stdout.flush()
        if exc_type is None and self.show_completion_message:
            print(f"{S}✓ {t('operation_completed')}{R}\n")

def print_user_banner(username, status_info):
    """Imprime el banner de bienvenida del usuario con su información de plan."""
    clear_screen()
    banner_char = "═"
    draxion_text = f"\033[1;96mD R A X I O N\033[0m"
    welcome_text_raw = t("welcome_banner", username=username.upper())
    
    print(f"\n{T}╔{banner_char * (WIDTH - 2)}╗{R}")
    padding = (WIDTH - 2 - get_visual_length(draxion_text)) // 2
    if padding < 0: padding = 0
    draxion_line = f"{ ' ' * padding}{draxion_text}{' ' * (WIDTH - 2 - get_visual_length(draxion_text) - padding)}"
    print(f"{T}║{R}{draxion_line}{T}║{R}")
    
    if len(welcome_text_raw) > WIDTH - 4:
        welcome_text_raw = welcome_text_raw[:WIDTH - 7] + "..."
    welcome_text_colored = f"{O}{welcome_text_raw}{R}" 
    padding = (WIDTH - 2 - get_visual_length(welcome_text_raw)) // 2
    if padding < 0: padding = 0
    left_pad = ' ' * padding
    right_pad = ' ' * (WIDTH - 2 - get_visual_length(welcome_text_raw) - padding)
    print(f"{T}║{R}{left_pad}{welcome_text_colored}{right_pad}{T}║{R}")
    print(f"{T}╟{banner_char * (WIDTH - 2)}╢{R}")

    if status_info:
        plan = status_info.get('plan_nombre', 'N/A')
        uso_bytes = status_info.get('uso_bytes', 0)
        limite_bytes = status_info.get('limite_bytes', 0)

        uso_legible = bytes_a_legible(uso_bytes)
        limite_legible = bytes_a_legible(limite_bytes) if limite_bytes > 0 else t('unlimited')
        
        plan_text = f"{t('plan')}: {O}{plan}{R}"
        usage_text = f"{t('usage')}: {O}{uso_legible}{R} {t('of')} {O}{limite_legible}{R}"
        
        plan_padding = (WIDTH - 2 - get_visual_length(plan_text)) // 2
        usage_padding = (WIDTH - 2 - get_visual_length(usage_text)) // 2

        print(f"{T}║{' ' * plan_padding}{plan_text}{' ' * (WIDTH - 2 - get_visual_length(plan_text) - plan_padding)}{T}║{R}")
        print(f"{T}║{' ' * usage_padding}{usage_text}{' ' * (WIDTH - 2 - get_visual_length(usage_text) - usage_padding)}{T}║{R}")

    print(f"{T}╚{banner_char * (WIDTH - 2)}╝{R}\n")

def print_api_error(response, default_message="Error en la operación"):
    """Imprime un error de API de forma formateada."""
    try:
        if response is None:
            print(f"\n{E}{t('server_not_responding')}{R}")
            return
        error_data = response.json()
        error_msg = error_data.get('error', default_message)
        detalles = error_data.get('detalles', '')
        print(f"\n{E}Error: {error_msg}{R}")
        if detalles:
            if isinstance(detalles, dict):
                for key, value in detalles.items():
                    print(f"{E}- {key.capitalize()}: {', '.join(value)}{R}")
            elif isinstance(detalles, list):
                 print(f"{E}Detalles: {', '.join(detalles)}{R}")
            else:
                 print(f"{E}Detalles: {detalles}{R}")
    except json.JSONDecodeError:
        print(f"\n{E}{default_message}. Código: {response.status_code}{R}")

def print_progress_bar(iteration, total, prefix='', suffix='', length=50, fill='█'):
    """Imprime una barra de progreso en la consola."""
    if total == 0: total = 1 # Evitar división por cero
    percent = ("{0:0.1f}").format(100 * (iteration / float(total)))
    filled_length = int(length * iteration // total)
    bar = fill * filled_length + '-' * (length - filled_length)
    # Usar código de escape ANSI para limpiar la línea (\x1b[2K) y volver al inicio (\r)
    sys.stdout.write(f'\x1b[2K\r{T}{prefix} |{bar}| {percent}% {suffix}{R}')
    sys.stdout.flush()
    if iteration == total:
        sys.stdout.write('\n')
