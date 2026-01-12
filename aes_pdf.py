import streamlit as st
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import scrypt

# --- Fungsi Inti Kriptografi ---
def generate_key(password, salt):
    return scrypt(password, salt, key_len=32, N=2**14, r=8, p=1)

def encrypt_data(data, password):
    salt = os.urandom(16)
    key = generate_key(password, salt)
    cipher = AES.new(key, AES.MODE_CBC)
    encrypted_payload = cipher.encrypt(pad(data, AES.block_size))
    # Menggabungkan salt + IV + ciphertext menjadi satu kesatuan byte
    return salt + cipher.iv + encrypted_payload

def decrypt_data(combined_data, password):
    try:
        salt = combined_data[:16]
        iv = combined_data[16:32]
        encrypted_payload = combined_data[32:]
        
        key = generate_key(password, salt)
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        return unpad(cipher.decrypt(encrypted_payload), AES.block_size)
    except:
        return None

# --- Tampilan Web Streamlit ---
st.set_page_config(page_title="AES PDF Encryptor", page_icon="🔐")

st.title("Enkripsi & Dekripsi AES-256")
st.write("UAS Kriptografi - Enkripsi File PDF sebagai Binary Data.")

tab1, tab2 = st.tabs(["Enkripsi", "Dekripsi"])

with tab1:
    st.header("Enkripsi File")
    uploaded_file = st.file_uploader("Pilih file PDF asli", type=["pdf"])
    password_enc = st.text_input("Masukkan Password Enkripsi", type="password", key="enc_pass")
    
    if st.button("Proses Enkripsi"):
        if uploaded_file and password_enc:
            file_bytes = uploaded_file.read()
            encrypted_result = encrypt_data(file_bytes, password_enc)
            
            st.success("File Berhasil Dienkripsi!")
            st.download_button(
                label="Download File Terenkripsi (.enc)",
                data=encrypted_result,
                file_name=f"{uploaded_file.name}.enc",
                mime="application/octet-stream"
            )
        else:
            st.error("Mohon unggah file dan masukkan password.")

with tab2:
    st.header("Dekripsi File")
    encrypted_file = st.file_uploader("Pilih file terenkripsi (.enc)", type=["enc"])
    password_dec = st.text_input("Masukkan Password Dekripsi", type="password", key="dec_pass")
    
    if st.button("Proses Dekripsi"):
        if encrypted_file and password_dec:
            enc_bytes = encrypted_file.read()
            decrypted_result = decrypt_data(enc_bytes, password_dec)
            
            if decrypted_result:
                st.success("Dekripsi Berhasil! Password Cocok.")
                st.download_button(
                    label="Download PDF Hasil Dekripsi",
                    data=decrypted_result,
                    file_name="hasil_dekripsi.pdf",
                    mime="application/pdf"
                )
            else:
                st.error("Gagal Dekripsi! Password salah atau data rusak.")
        else:
            st.error("Mohon unggah file .enc dan masukkan password.")

st.divider()
st.caption("Dibuat untuk Simulasi UAS Kriptografi - Algoritma AES Mode CBC")