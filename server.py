import threading
from tkinter import *
from tkinter import scrolledtext, ttk
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
    global conn, client_public_key, message_display, show_encrypted_var
    while True:
        try:
            encrypted_msg = conn.recv(1024)
            if not encrypted_msg:
                print("Bağlantı kapatıldı.")
                break
            decrypted_msg = decrypt_message(encrypted_msg, private_key)
            if show_encrypted_var.get():
                # Hem şifreli hem de çözülmüş mesajı göster
                message_display.insert(INSERT, f"Encrypted message from client: {encrypted_msg.hex()}\nDecrypted message: {decrypted_msg.decode()}\n")
            else:
                # Sadece çözülmüş mesajı göster
                message_display.insert(INSERT, f"Decrypted message from client: {decrypted_msg.decode()}\n")
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

def send_message():
    global conn, client_public_key
    if conn and client_public_key:
        msg = message_input.get("1.0", 'end-1c').encode()
        encrypted_msg = encrypt_message(msg, client_public_key)
        conn.sendall(encrypted_msg)
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

send_button = Button(root, text="Send Message", command=send_message)
send_button.grid(column=0, row=2, pady=10)

show_encrypted_var = IntVar()
show_encrypted = ttk.Checkbutton(root, text="Show Encrypted", variable=show_encrypted_var, onvalue=1, offvalue=0)
show_encrypted.grid(column=0, row=3, pady=10)

threading.Thread(target=start_server, daemon=True).start()

root.mainloop()
