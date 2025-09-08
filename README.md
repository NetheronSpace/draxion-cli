# Draxion - Command-Line Interface

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/release/python-390/)

---

> **⚠️ Estado del Proyecto: Prototipo Experimental**
> 
> Este cliente es una prueba de concepto funcional. Aunque las bases criptográficas y la arquitectura son sólidas, hay muchas áreas que necesitan ser pulidas y mejoradas antes de considerarse una versión de producción. No es un producto oficial.

---

## 📜 Descripción

Este repositorio contiene el código fuente para el cliente de línea de comandos (CLI) de **Draxion**, un servicio de almacenamiento seguro de archivos en la nube. El cliente está diseñado bajo una filosofía de **confianza cero** (*zero-trust*) y **criptografía de extremo a extremo** (*E2EE*), donde el cliente es el único responsable de la gestión de claves y el cifrado de datos.

### Aclaración sobre el Idioma

> Una parte significativa del código fue escrita originalmente en español. Se está trabajando para estandarizar todo a inglés, pero aún pueden quedar restos del idioma original. Esto se corregirá en futuras actualizaciones.

## ✨ Características Principales

*   **Autenticación Zero-Knowledge:** Demuestra la posesión de la contraseña maestra sin revelarla al servidor, usando un protocolo ZKP.
*   **Cifrado End-to-End:** Los archivos se cifran y descifran localmente. El servidor solo almacena blobs de datos ilegibles.
*   **Gestión de Archivos Concurrente:** Sube y descarga archivos en paralelo para mayor eficiencia.
*   **Recuperación de Desastres:** Implementa el Esquema Secreto de Shamir (SSS) para dividir la clave maestra en fragmentos recuperables.
*   **Compartición Segura:** Comparte archivos con otros usuarios reenviando la clave del archivo, cifrada con la clave pública del destinatario.

## ⚙️ Instalación y Configuración

1.  **Clonar el Repositorio:**
    ```sh
    git clone https://github.com/NetheronSpace/draxion-cli.git
    cd draxion-cli
    ```

2.  **Crear Entorno Virtual:**
    ```sh
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **Instalar Dependencias:**
    ```sh
    pip install -r requirements.txt
    ```

4.  **Configurar la API:**
    Abre el archivo `src/config.py` y establece el valor de la variable `SERVER_URL` para que apunte a la dirección de tu servidor Draxion.

## 🚀 Uso Básico

*   **Ver todos los comandos disponibles:**
    ```sh
    python3 cliente.py --help
    ```

*   **Registrar una nueva cuenta:**
    ```sh
    python3 cliente.py register
    ```

*   **Iniciar sesión en tu cuenta:**
    ```sh
    python3 cliente.py login
    ```
