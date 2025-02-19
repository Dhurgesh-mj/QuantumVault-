import socket
import time
import argparse
from cryptography.hazmat.decrepit.ciphers import algorithms as deprecated_algorithms
from cryptography.hazmat.primitives.asymmetric import rsa , padding as rsa_padding 
from cryptography.hazmat.primitives import hashes,serialization,padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher , algorithms,modes
from cryptography.hazmat.backends import default_backend
import subprocess
import sys
import os
import time
import socket
import platform
from rich.console import Console
from tqdm import tqdm
import colorama
from colorama import Fore, Style
colorama.init(autoreset=True) 
YELLOW = Fore.YELLOW
RED = Fore.RED
GREEN = Fore.GREEN
RESET = Style.RESET_ALL
BLUE = Fore.BLUE
def banner():
    banner = rf'''{RED}
 _____ _   _  ___   _   _ _____ _   ____  ___      _   _  ___  _   _ _    _____ 
|  _  | | | |/ _ \ | \ | |_   _| | | |  \/  |     | | | |/ _ \| | | | |  |_   _|
| | | | | | / /_\ \|  \| | | | | | | | .  . |     | | | / /_\ \ | | | |    | |  
| | | | | | |  _  || . ` | | | | | | | |\/| |     | | | |  _  | | | | |    | |  
\ \/' / |_| | | | || |\  | | | | |_| | |  | |     \ \_/ / | | | |_| | |____| |  
 \_/\_\\___/\_| |_/\_| \_/ \_/  \___/\_|  |_/      \___/\_| |_/\___/\_____/\_/       -V1
                                                                                                             {RESET}'''
    print(banner)
def ip_check():
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    return local_ip
def typing_effect(sentance,colour="",delay=0.03):
    for char in sentance:
        sys.stdout.write(f"{colour}{char}{RESET}")
        sys.stdout.flush()
        time.sleep(delay)
    print()
def sys_information():
    os_name = platform.system()
    os_version = platform.version()
    os_release = platform.release()
    os_machine = platform.machine()
    local_ip = ip_check()
    typing_effect("\n====================================================",GREEN)
    typing_effect("                     SYSTEM DETAILS               ",BLUE)  
    typing_effect("====================================================",GREEN)
    typing_effect(f"Operating System : {os_name}",BLUE)
    typing_effect(f"Version          : {os_version}",BLUE)
    typing_effect(f"Release          : {os_release}",BLUE)
    typing_effect(f"Machine          : {os_machine}",BLUE)
    typing_effect(f"Local-IPV4       : {local_ip}",BLUE)
    typing_effect("====================================================",GREEN)
def calculating_animation(duration=3):
    console = Console()
    with console.status("[bold green]STARTING...[/bold green]", spinner="growVertical",spinner_style="bold red"):
            time.sleep(duration)
def generate_rsa_key(path):
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=4096, backend=default_backend()
    )
    public_key = private_key.public_key()
    os.makedirs(path,exist_ok=True)
    with open(f"{path}/private_key.pem","wb") as priv_file :
        priv_file.write(
            private_key.private_bytes(
                encoding = serialization.Encoding.PEM,
                format = serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(), 
            )
        )
    with open(f"{path}/public_key.pem","wb") as pub_key:
        pub_key.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
    typing_effect("[+] Key's have been saved ..........",GREEN)
def load_keys(path):
    with open(f"{path}/private_key.pem","rb") as priv_file :
        private_key = serialization.load_pem_private_key(
            priv_file.read(),password = None , backend = default_backend()
        )
    with open(f"{path}/public_key.pem","rb") as pub_file:
        public_key = serialization.load_pem_public_key(
            pub_file.read(), backend = default_backend()
        )
    return private_key , public_key

def aes_encrypt(data, key):
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())  # ✅ Fixed AES import
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return iv + ciphertext, encryptor.tag

def aes_decrypt(encrypted_data, key, tag):
    iv = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())  # ✅ Fixed AES import
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def chacha20_encrypt(data, key):
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())  # ✅ Fixed ChaCha20 import
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data)
    return nonce + ciphertext

def chacha20_decrypt(encrypted_data, key):
    nonce = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())  # ✅ Fixed ChaCha20 import
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext)

def blowfish_encrypt(data, key):
    cipher = Cipher(deprecated_algorithms.Blowfish(key), modes.ECB(), backend=default_backend())  # ✅ Use deprecated import for Blowfish
    encryptor = cipher.encryptor()
    padder = sym_padding.PKCS7(deprecated_algorithms.Blowfish.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    return encryptor.update(padded_data) + encryptor.finalize()

def blowfish_decrypt(encrypted_data, key):
    cipher = Cipher(deprecated_algorithms.Blowfish(key), modes.ECB(), backend=default_backend())  # ✅ Use deprecated import for Blowfish
    decryptor = cipher.decryptor()
    unpadder = sym_padding.PKCS7(deprecated_algorithms.Blowfish.block_size).unpadder()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    return unpadder.update(decrypted_data) + unpadder.finalize()

def multi_layer_encrypt(data, aes_key, chacha_key, blowfish_key):
    aes_cipher, aes_tag = aes_encrypt(data, aes_key)
    chacha_cipher = chacha20_encrypt(aes_cipher + aes_tag, chacha_key)
    final_cipher = blowfish_encrypt(chacha_cipher, blowfish_key)
    return final_cipher

def multi_layer_decrypt(encrypted_data, aes_key, chacha_key, blowfish_key):
    blowfish_plain = blowfish_decrypt(encrypted_data, blowfish_key)
    chacha_plain = chacha20_decrypt(blowfish_plain, chacha_key)
    aes_cipher = chacha_plain[:-16]  # Removing tag
    aes_tag = chacha_plain[-16:]
    final_plain = aes_decrypt(aes_cipher, aes_key, aes_tag)
    return final_plain
def rsa_encrypt(data,public_key):
    return public_key.encrypt(
        data,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

def rsa_decrypt(encrypted_data,private_key):
    return private_key.decrypt(
        encrypted_data,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        ),
    )
def secure_transfer(server_ip, server_port, file_path):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server_ip, server_port))
        public_key_data = b""
        while True:
            chunk = s.recv(4096)
            if b"--END-KEY--" in chunk:
                public_key_data += chunk.split(b"--END-KEY--")[0]
                break
            public_key_data += chunk
        
        public_key = serialization.load_pem_public_key(public_key_data, backend=default_backend())
        aes_key = os.urandom(32)  # AES-256 key
        chacha_key = os.urandom(32)  # ChaCha20 key
        blowfish_key = os.urandom(16) 
        encrypted_aes_key = rsa_encrypt(aes_key, public_key)
        encrypte_chacha_key = rsa_encrypt(chacha_key,public_key)
        encrypte_blowfish_key = rsa_encrypt(blowfish_key,public_key)
        file_name = os.path.basename(file_path).encode()
        encrypted_file_name = multi_layer_encrypt(file_name, aes_key,chacha_key,blowfish_key)

        with open(file_path, "rb") as file:
            file_data = file.read()

        encrypted_file_data = multi_layer_encrypt(file_data, aes_key,chacha_key,blowfish_key)

        # Send encrypted AES key & file metadata
        s.sendall(encrypted_aes_key + b"---END---" + encrypte_chacha_key + b"---END---" + encrypte_blowfish_key + b"---END---" + encrypted_file_name )
        
        # Send encrypted file data with progress bar
        file_size = len(encrypted_file_data)
        progress_bar = tqdm(total=file_size, unit="B", unit_scale=True, desc="Sending")

        bytes_sent = 0
        chunk_size = 4096
        for i in range(0, file_size, chunk_size):
            chunk = encrypted_file_data[i:i + chunk_size]
            s.sendall(chunk)
            bytes_sent += len(chunk)
            progress_bar.update(len(chunk))
        
        progress_bar.close()
        print("[+] File transferred securely.")

def secure_receive(server_port, private_key_path):
    private_key, public_key = load_keys(private_key_path)

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("0.0.0.0", server_port))
        s.listen(1)
        print(f"[+] Listening on port {server_port}...")

        conn, addr = s.accept()
        with conn:
            print(f"[+] Connection from {addr}")

            conn.sendall(public_pem + b"--END-KEY--")
            print("public key sent ......")

            data = b""
            while True:
                chunk = conn.recv(4096)
                if b"---END---" in chunk:
                    data += chunk
                    break
                data += chunk
            parts = data.split(b"---END---")

            if len(parts) != 4:
                print(f"[-] Unexpected number of parts received: {len(parts)}. Data: {parts}")
                return

            encrypted_aes_key, encrypte_chacha_key, encrypte_blowfish_key, encrypted_file_name = parts


            #encrypted_aes_key, encrypte_chacha_key, encrypte_blowfish_key, encrypted_file_name = parts

            #encrypted_aes_key , encrypte_chacha_key, encrypte_blowfish_key , encrypted_file_name = data.split(b"---END---")

            aes_key = rsa_decrypt(encrypted_aes_key, private_key)
            chacha_key = rsa_decrypt(encrypte_chacha_key,private_key)
            blowfish_key = rsa_decrypt(encrypte_blowfish_key,private_key)
            file_name = multi_layer_decrypt(encrypted_file_name, aes_key ,chacha_key,blowfish_key).decode()
            file_data = b""

            # Receive encrypted file data with progress bar
            print("[+] Receiving file...")
            progress_bar = tqdm(unit="B", unit_scale=True, desc="Receiving")

            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                file_data += chunk
                progress_bar.update(len(chunk))

            progress_bar.close()

            decrypted_file_data = multi_layer_decrypt(file_data, aes_key,chacha_key,blowfish_key)

            with open(file_name, "wb") as file:
                file.write(decrypted_file_data)

            print(f"[+] File received and saved as: {file_name}")


def main():
    parser = argparse.ArgumentParser(description="Secure File Transfer CLI Tool")
    subparsers = parser.add_subparsers(dest="command")

    # Generate RSA key pair
    gen_keys_parser = subparsers.add_parser("generate-keys", help="Generate RSA key pair")
    gen_keys_parser.add_argument("--path", default="keys", help="Path to save keys")

    # Send file securely
    send_parser = subparsers.add_parser("send", help="Send a file securely")
    send_parser.add_argument("--server-ip", required=True, help="Server IP address")
    send_parser.add_argument("--server-port", type=int, required=True, help="Server port")
    send_parser.add_argument("--file-path", required=True, help="Path to the file to send")

    # Receive file securely
    receive_parser = subparsers.add_parser("receive", help="Receive a file securely")
    receive_parser.add_argument("--server-port", type=int, required=True, help="Port to listen on")
    receive_parser.add_argument("--private-key-path", required=True, help="Path to the private key")

    gui_load = subparsers.add_parser("gui", help="Open the GUI for the tool")
    args = parser.parse_args()

    if args.command == "generate-keys":
        generate_rsa_key(args.path)
    elif args.command == "send":
        secure_transfer(args.server_ip, args.server_port, args.file_path)
    elif args.command == "receive":
        secure_receive(args.server_port, args.private_key_path)
    elif args.command == "gui":
        typing_effect("[+] Lanunching Gui.......... Please Wait ")
        calculating_animation()
        subprocess.run([sys.executable, "gui.py"])
    else:
        parser.print_help()


if __name__ == "__main__":
    os.system("clear" if os.name == "posix" else "cls")
    banner()
    sys_information()
    main()
