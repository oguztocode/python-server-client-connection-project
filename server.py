import threading
from tkinter import *
from tkinter import scrolledtext
from socket import socket, AF_INET, SOCK_STREAM
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

global conn, client_public_key
conn = None
client_public_key = None

def encrypt_message(message, public_key):
    return public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt_message(encrypted_message, private_key):
    return private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def handle_client():
    global conn, client_public_key, message_display
    while True:
        try:
            msg_type_encoded = conn.recv(1024)
            if not msg_type_encoded:
                print("Bağlantı kapatıldı.")
                break
            # Mesaj tipine göre işlem yap
            if msg_type_encoded.startswith(b"encrypted:"):
                encrypted_msg = msg_type_encoded[len("encrypted:"):]
                decrypted_msg = decrypt_message(encrypted_msg, private_key)
                message_display.insert(INSERT, f"Client sent an encrypted message: {encrypted_msg.hex()}\nDecrypted message: {decrypted_msg.decode()}\n")
            elif msg_type_encoded.startswith(b"plain:"):
                plain_msg = msg_type_encoded[len("plain:"):]
                message_display.insert(INSERT, f"Client sent a plain message: {plain_msg.decode()}\n")
        except Exception as e:
            print(e)
            break

def start_server():
    global conn, client_public_key
    server_socket = socket(AF_INET, SOCK_STREAM)
    server_socket.bind(('localhost', 12345))
    server_socket.listen()
    print("Sunucu bağlantı için hazır...")
    conn, addr = server_socket.accept()
    with conn:
        print(f"{addr} ile bağlantı kuruldu")
        conn.sendall(public_key_pem)
        client_public_key_pem = conn.recv(1024)
        client_public_key = serialization.load_pem_public_key(client_public_key_pem, backend=default_backend())
        handle_client()

def send_message(encrypted=False):
    global conn, client_public_key
    if conn and client_public_key:
        msg = message_input.get("1.0", 'end-1c').encode()
        if encrypted:
            encrypted_msg = encrypt_message(msg, client_public_key)
            conn.sendall(b"encrypted:" + encrypted_msg)
        else:
            conn.sendall(b"plain:" + msg)
        message_input.delete("1.0", END)
    else:
        print("Bağlantı kurulamadı veya istemcinin public key'i yok.")

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
public_key = private_key.public_key()
public_key_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

root = Tk()
root.title("Server")

message_display = scrolledtext.ScrolledText(root, width=70, height=20)
message_display.grid(column=0, row=0, pady=10, padx=10)

message_input = Text(root, height=3)
message_input.grid(column=0, row=1, pady=10, padx=10)

send_button = Button(root, text="Normal Gönder", command=lambda: send_message(False))
send_button.grid(column=0, row=2, pady=10)

send_encrypted_button = Button(root, text="Gizli Gönder", command=lambda: send_message(True))
send_encrypted_button.grid(column=0, row=3, pady=10)

threading.Thread(target=start_server, daemon=True).start()

root.mainloop()
