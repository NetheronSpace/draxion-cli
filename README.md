# Draxion - Command-Line Interface

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/release/python-390/)

---

> **⚠️ Project Status: Experimental Prototype**
> 
> This client is a functional proof of concept. Although the cryptographic foundations and architecture are solid, there are many areas that need to be polished and improved before it can be considered a production release. This is not an official product.

---

## 📜 Description

This repository contains the source code for the command-line interface (CLI) client for **Draxion**, a secure cloud file storage service. The client is designed under a **zero-trust** and **end-to-end encryption (E2EE)** philosophy, where the client is solely responsible for key management and data encryption.

### Language Clarification

> A significant part of the code was originally written in Spanish. Efforts are underway to standardize everything to English, but remnants of the original language may still exist. This will be corrected in future updates.

## ✨ Key Features

*   **Zero-Knowledge Authentication:** Proves possession of the master password without revealing it to the server, using a ZKP protocol.
*   **End-to-End Encryption:** Files are encrypted and decrypted locally. The server only stores unreadable data blobs.
*   **Concurrent File Management:** Upload and download files in parallel for greater efficiency.
*   **Disaster Recovery:** Implements Shamir's Secret Sharing (SSS) to split the master key into recoverable fragments.
*   **Secure Sharing:** Share files with other users by forwarding the file key, encrypted with the recipient's public key.

## ⚙️ Installation and Setup

1.  **Clone the Repository:**
    ```sh
    git clone https://github.com/NetheronSpace/draxion-cli.git
    cd draxion-cli
    ```

2.  **Create a Virtual Environment:**
    ```sh
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **Install Dependencies:**
    ```sh
    pip install -r requirements.txt
    ```

4.  **Configure the API:**
    Open the `src/config.py` file and set the value of the `SERVER_URL` variable to point to your Draxion server's address.

## 🚀 Basic Usage

*   **View all available commands:**
    ```sh
    python3 cliente.py --help
    ```

*   **Register a new account:**
    ```sh
    python3 cliente.py register
    ```

*   **Log into your account:**
    ```sh
    python3 cliente.py login
    ```