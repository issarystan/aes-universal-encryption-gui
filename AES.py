import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
import os

BLOCK_SIZE = AES.block_size 

def generate_key(password, salt=b'static_salt'):
    return PBKDF2(password, salt, dkLen=16)

def encrypt_file():
    password = password_entry.get()
    if not password:
        messagebox.showwarning("Warning", "Enter a password!")
        return

    filepath = filedialog.askopenfilename()
    if not filepath:
        return

    with open(filepath, "rb") as f:
        data = f.read()

    key = generate_key(password)
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = iv + cipher.encrypt(pad(data, BLOCK_SIZE))

    filename = os.path.basename(filepath)
    encrypted_path = os.path.join("encrypted", filename + ".enc")

    with open(encrypted_path, "wb") as f:
        f.write(encrypted)

    messagebox.showinfo("Success", f"Encrypted and saved as:\n{encrypted_path}")

def decrypt_file():
    password = password_entry.get()
    if not password:
        messagebox.showwarning("Warning", "Enter a password!")
        return

    filepath = filedialog.askopenfilename(filetypes=[("Encrypted files", "*.enc")])
    if not filepath:
        return

    with open(filepath, "rb") as f:
        data = f.read()

    iv = data[:BLOCK_SIZE]
    ciphertext = data[BLOCK_SIZE:]
    key = generate_key(password)

    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(ciphertext), BLOCK_SIZE)
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {e}")
        return

    original_name = os.path.basename(filepath).replace(".enc", "")
    decrypted_path = os.path.join("decrypted", original_name)

    with open(decrypted_path, "wb") as f:
        f.write(decrypted)

    messagebox.showinfo("Success", f"Decrypted and saved as:\n{decrypted_path}")

# GUI бөлігі
window = tk.Tk()
window.title("AES Universal File Encryption")
window.geometry("420x220")

tk.Label(window, text="Enter password:").pack(pady=5)
password_entry = tk.Entry(window, show="*", width=40)
password_entry.pack(pady=5)

tk.Button(window, text="Encrypt any file", command=encrypt_file).pack(pady=10)
tk.Button(window, text="Decrypt .enc file", command=decrypt_file).pack(pady=5)

window.mainloop()
