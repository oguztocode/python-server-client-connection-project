import threading
from tkinter import *
from tkinter import scrolledtext, ttk
from socket import socket, AF_INET, SOCK_STREAM
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

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

def send_message():
    message_to_send = message_input.get("1.0", 'end-1c').encode()
    encrypted_message = encrypt_message(message_to_send, server_public_key)
    client_socket.sendall(encrypted_message)
    message_input.delete("1.0", END)

def receive_response():
    while True:
        encrypted_response = client_socket.recv(1024)
        if not encrypted_response:
            print("Server closed the connection.")
            break
        decrypted_response = decrypt_message(encrypted_response, private_key)
        if show_encrypted_var.get():
            display_message = f"Encrypted response from server: {encrypted_response.hex()}\nDecrypted response: {decrypted_response.decode('utf-8')}\n"
        else:
            display_message = f"Decrypted response from server: {decrypted_response.decode('utf-8')}\n"
        message_display.insert(INSERT, display_message)

client_socket = socket(AF_INET, SOCK_STREAM)
client_socket.connect(('localhost', 12345))

server_public_key_pem = client_socket.recv(1024)
server_public_key = serialization.load_pem_public_key(server_public_key_pem, backend=default_backend())

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
public_key = private_key.public_key()
public_key_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

client_socket.sendall(public_key_pem)

root = Tk()
root.title("Client")

message_display = scrolledtext.ScrolledText(root, width=70, height=20)
message_display.grid(column=0, row=0, pady=10, padx=10)

message_input = Text(root, height=3)
message_input.grid(column=0, row=1, pady=10, padx=10)

send_button = Button(root, text="Send Message", command=send_message)
send_button.grid(column=0, row=2, pady=10)

show_encrypted_var = IntVar()
show_encrypted = ttk.Checkbutton(root, text="Show Decrypted", variable=show_encrypted_var, onvalue=1, offvalue=0)
show_encrypted.grid(column=0, row=3, pady=10)

threading.Thread(target=receive_response, daemon=True).start()

root.mainloop()
