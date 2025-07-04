import customtkinter as ctk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

class SteganographyApp:
    def __init__(self):
        # Konfigurasi tema CustomTkinter
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # Inisialisasi jendela utama
        self.root = ctk.CTk()
        self.root.title("Alat Steganografi LSB (dengan Enkripsi)")
        self.root.geometry("800x600")
        self.root.resizable(True, True)

        # Variabel untuk menyimpan path gambar dan pesan
        self.cover_image_path = None
        self.secret_image_path = None # Ini bisa jadi output image path
        self.secret_message = ctk.StringVar() # Untuk input pesan
        self.encryption_key = ctk.StringVar() # Untuk input kunci enkripsi

        self.setup_gui()

    def setup_gui(self):
        # Frame utama
        main_frame = ctk.CTkFrame(self.root)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Tabview untuk Sembunyikan dan Ekstrak
        self.tabview = ctk.CTkTabview(main_frame)
        self.tabview.pack(fill="both", expand=True)

        self.tabview.add("Sembunyikan Pesan (Encode)")
        self.tabview.add("Ekstrak Pesan (Decode)")

        # --- Tab Sembunyikan Pesan ---
        encode_tab = self.tabview.tab("Sembunyikan Pesan (Encode)")

        # Bagian Pilih Gambar Cover
        cover_frame = ctk.CTkFrame(encode_tab)
        cover_frame.pack(pady=10, fill="x")
        self.cover_label = ctk.CTkLabel(cover_frame, text="Belum ada gambar yang dipilih")
        self.cover_label.pack(side="left", padx=10)
        select_cover_button = ctk.CTkButton(cover_frame, text="Pilih Gambar Cover", command=self.select_cover_image)
        select_cover_button.pack(side="right", padx=10)

        # Input Pesan Rahasia
        message_label = ctk.CTkLabel(encode_tab, text="Masukkan Pesan Rahasia:")
        message_label.pack(pady=(10, 5))
        self.message_textbox = ctk.CTkTextbox(encode_tab, height=100)
        self.message_textbox.pack(fill="x", padx=10)

        # Input Kunci Enkripsi
        key_label = ctk.CTkLabel(encode_tab, text="Masukkan Kunci Enkripsi (min. 16 karakter):")
        key_label.pack(pady=(10, 5))
        self.key_entry_encode = ctk.CTkEntry(encode_tab, textvariable=self.encryption_key, show="*") # show="*" untuk sembunyikan karakter
        self.key_entry_encode.pack(fill="x", padx=10)

        # Tombol Sembunyikan & Simpan
        encode_button = ctk.CTkButton(encode_tab, text="Sembunyikan & Simpan...", command=self.hide_message_with_encryption)
        encode_button.pack(pady=20)

        # --- Tab Ekstrak Pesan ---
        decode_tab = self.tabview.tab("Ekstrak Pesan (Decode)")

        # Bagian Pilih Gambar untuk Ekstrak
        extract_frame = ctk.CTkFrame(decode_tab)
        extract_frame.pack(pady=10, fill="x")
        self.extract_label = ctk.CTkLabel(extract_frame, text="Belum ada gambar yang dipilih")
        self.extract_label.pack(side="left", padx=10)
        select_extract_button = ctk.CTkButton(extract_frame, text="Pilih Gambar untuk Ekstrak", command=self.select_image_to_extract)
        select_extract_button.pack(side="right", padx=10)

        # Input Kunci Dekripsi
        key_label_decode = ctk.CTkLabel(decode_tab, text="Masukkan Kunci Dekripsi:")
        key_label_decode.pack(pady=(10, 5))
        self.key_entry_decode = ctk.CTkEntry(decode_tab, show="*")
        self.key_entry_decode.pack(fill="x", padx=10)

        # Tombol Ekstrak Pesan
        decode_button = ctk.CTkButton(decode_tab, text="Ekstrak Pesan", command=self.extract_message_with_decryption)
        decode_button.pack(pady=20)

        # Tampilan Pesan Hasil Ekstraksi
        extracted_message_label = ctk.CTkLabel(decode_tab, text="Pesan Hasil Ekstraksi:")
        extracted_message_label.pack(pady=(10, 5))
        self.extracted_message_textbox = ctk.CTkTextbox(decode_tab, height=100)
        self.extracted_message_textbox.pack(fill="x", padx=10)
        self.extracted_message_textbox.configure(state="disabled") # Non-editable

    def select_cover_image(self):
        file_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.bmp")])
        if file_path:
            self.cover_image_path = file_path
            self.cover_label.configure(text=os.path.basename(file_path))
            messagebox.showinfo("Informasi", f"Gambar Cover dipilih: {os.path.basename(file_path)}")

    def select_image_to_extract(self):
        file_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.bmp")])
        if file_path:
            self.secret_image_path = file_path
            self.extract_label.configure(text=os.path.basename(file_path))
            messagebox.showinfo("Informasi", f"Gambar untuk Ekstrak dipilih: {os.path.basename(file_path)}")

    # --- FUNGSI KRIPTOGRAFI ---
    def encrypt_message(self, message, key):
        try:
            # Kunci harus 16, 24, atau 32 byte untuk AES. Kita akan padding jika kurang.
            # Menggunakan SHA256 untuk memastikan key memiliki panjang yang benar dan deterministik
            from hashlib import sha256
            key_hash = sha256(key.encode('utf-8')).digest()[:16] # Ambil 16 byte pertama untuk AES-128

            cipher = AES.new(key_hash, AES.MODE_CBC)
            ct_bytes = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
            return cipher.iv + ct_bytes # Gabungkan IV dengan ciphertext
        except Exception as e:
            messagebox.showerror("Error Enkripsi", f"Gagal mengenkripsi pesan: {e}")
            return None

    def decrypt_message(self, enc_message, key):
        try:
            from hashlib import sha256
            key_hash = sha256(key.encode('utf-8')).digest()[:16] # Ambil 16 byte pertama untuk AES-128

            iv = enc_message[:AES.block_size]
            ciphertext = enc_message[AES.block_size:]
            cipher = AES.new(key_hash, AES.MODE_CBC, iv=iv)
            pt_bytes = unpad(cipher.decrypt(ciphertext), AES.block_size)
            return pt_bytes.decode('utf-8')
        except Exception as e:
            messagebox.showerror("Error Dekripsi", f"Gagal mendekripsi pesan. Pastikan kunci dan gambar benar. Error: {e}")
            return None

    # --- FUNGSI STEGANOGRAFI LSB ---
    def hide_message(self, image_path, message):
        """
        Menyembunyikan pesan dalam gambar menggunakan LSB.
        Asumsi: pesan sudah dalam bentuk byte terenkripsi.
        Kita akan tambahkan prefix panjang pesan agar mudah diekstrak.
        """
        if not image_path:
            messagebox.showerror("Error", "Pilih gambar cover terlebih dahulu.")
            return None

        try:
            img = Image.open(image_path).convert("RGB")
            width, height = img.size
            pixels = img.getdata()

            # Tambahkan panjang pesan sebagai 4 byte pertama
            # Ini penting agar saat ekstraksi kita tahu berapa banyak byte yang harus dibaca
            message_bytes = len(message).to_bytes(4, 'big') + message

            if len(message_bytes) * 8 > width * height * 3:
                messagebox.showerror("Error", "Pesan terlalu besar untuk gambar ini.")
                return None

            new_pixels = []
            message_index = 0
            message_bits = "".join([bin(byte)[2:].zfill(8) for byte in message_bytes])

            for pixel in pixels:
                new_pixel = list(pixel)
                for i in range(3): # Loop melalui R, G, B
                    if message_index < len(message_bits):
                        # Ambil bit LSB dari komponen warna dan ganti dengan bit pesan
                        # (pixel[i] & 0xFE) membersihkan bit LSB
                        # int(message_bits[message_index]) menambahkan bit pesan ke LSB
                        new_pixel[i] = (pixel[i] & 0xFE) | int(message_bits[message_index])
                        message_index += 1
                new_pixels.append(tuple(new_pixel))

            new_img = Image.new(img.mode, img.size)
            new_img.putdata(new_pixels)

            # Simpan gambar baru
            output_path = filedialog.asksaveasfilename(defaultextension=".png",
                                                       filetypes=[("PNG files", "*.png"), ("BMP files", "*.bmp")])
            if output_path:
                new_img.save(output_path)
                messagebox.showinfo("Berhasil", f"Pesan berhasil disembunyikan dan disimpan di:\n{output_path}")
                return output_path
            return None

        except Exception as e:
            messagebox.showerror("Error Steganografi", f"Gagal menyembunyikan pesan: {e}")
            return None

    def extract_message(self, image_path):
        """
        Mengekstrak pesan dari gambar menggunakan LSB.
        """
        if not image_path:
            messagebox.showerror("Error", "Pilih gambar untuk diekstrak terlebih dahulu.")
            return None

        try:
            img = Image.open(image_path).convert("RGB")
            pixels = img.getdata()

            extracted_bits = ""
            for pixel in pixels:
                for i in range(3): # Loop melalui R, G, B
                    extracted_bits += bin(pixel[i])[-1] # Ambil bit LSB

            # Ekstrak panjang pesan (4 byte pertama)
            # Pastikan ada cukup bit untuk panjang pesan
            if len(extracted_bits) < 32: # 4 bytes * 8 bits/byte = 32 bits
                messagebox.showerror("Error Ekstraksi", "Gambar tidak mengandung pesan yang tersembunyi atau rusak.")
                return None

            length_bits = extracted_bits[:32]
            message_length = int(length_bits, 2)

            # Ekstrak pesan sebenarnya
            start_index = 32 # Mulai setelah 4 byte panjang pesan
            # Pastikan ada cukup bit untuk pesan yang diekstrak
            if len(extracted_bits) < start_index + message_length * 8:
                 messagebox.showerror("Error Ekstraksi", "Panjang pesan yang terdeteksi tidak sesuai dengan isi gambar. Mungkin gambar rusak atau bukan hasil steganografi ini.")
                 return None

            message_bits = extracted_bits[start_index : start_index + message_length * 8]

            byte_array = bytearray()
            for i in range(0, len(message_bits), 8):
                byte = int(message_bits[i:i+8], 2)
                byte_array.append(byte)

            return bytes(byte_array)

        except Exception as e:
            messagebox.showerror("Error Ekstraksi", f"Gagal mengekstrak pesan: {e}")
            return None

    # --- INTEGRASI ENKRIPSI/DEKRIPSI DENGAN STEGANOGRAFI ---

    def hide_message_with_encryption(self):
        message = self.message_textbox.get("1.0", "end-1c") # Ambil semua teks dari textbox
        key = self.key_entry_encode.get()

        if not self.cover_image_path:
            messagebox.showerror("Error", "Pilih gambar cover terlebih dahulu.")
            return
        if not message.strip():
            messagebox.showerror("Error", "Pesan rahasia tidak boleh kosong.")
            return
        if not key.strip() or len(key) < 16:
            messagebox.showerror("Error", "Kunci enkripsi harus diisi dan minimal 16 karakter.")
            return

        encrypted_msg_bytes = self.encrypt_message(message, key)
        if encrypted_msg_bytes:
            self.hide_message(self.cover_image_path, encrypted_msg_bytes)

    def extract_message_with_decryption(self):
        key = self.key_entry_decode.get()

        if not self.secret_image_path:
            messagebox.showerror("Error", "Pilih gambar untuk diekstrak terlebih dahulu.")
            return
        if not key.strip():
            messagebox.showerror("Error", "Kunci dekripsi tidak boleh kosong.")
            return

        extracted_encrypted_bytes = self.extract_message(self.secret_image_path)
        if extracted_encrypted_bytes:
            decrypted_msg = self.decrypt_message(extracted_encrypted_bytes, key)
            if decrypted_msg:
                self.extracted_message_textbox.configure(state="normal") # Enable untuk diisi
                self.extracted_message_textbox.delete("1.0", "end")
                self.extracted_message_textbox.insert("1.0", decrypted_msg)
                self.extracted_message_textbox.configure(state="disabled") # Disable lagi
            else:
                self.extracted_message_textbox.configure(state="normal")
                self.extracted_message_textbox.delete("1.0", "end")
                self.extracted_message_textbox.insert("1.0", "Gagal mendekripsi. Pastikan kunci benar.")
                self.extracted_message_textbox.configure(state="disabled")
        else:
            self.extracted_message_textbox.configure(state="normal")
            self.extracted_message_textbox.delete("1.0", "end")
            self.extracted_message_textbox.insert("1.0", "Tidak ada pesan tersembunyi ditemukan atau gambar rusak.")
            self.extracted_message_textbox.configure(state="disabled")


    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = SteganographyApp()
    app.run()