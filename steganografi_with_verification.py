
import customtkinter as ctk
from tkinter import filedialog, messagebox
from PIL import Image
import os
import hashlib # Untuk menghitung hash gambar

# --- TAMBAHAN IMPORT UNTUK KRIPTOGRAFI ---
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from hashlib import sha256 # Digunakan untuk hashing kunci AES
# --- AKHIR TAMBAHAN IMPORT ---

class SteganographyApp:
    def __init__(self):
        # Konfigurasi tema CustomTkinter
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # Inisialisasi jendela utama
        self.root = ctk.CTk()
        self.root.title("Alat Steganografi LSB (dengan Enkripsi & Verifikasi)")
        self.root.geometry("800x600")
        self.root.resizable(True, True)
        
        # Variabel untuk menyimpan path file
        self.cover_image_path = ""
        self.secret_image_path = ""
        self.verify_image_path = "" # Path untuk gambar yang akan diverifikasi
        
        # --- TAMBAHAN VARIABEL UNTUK KUNCI ENKRIPSI ---
        self.encryption_key = ctk.StringVar() # Untuk input kunci enkripsi/dekripsi
        # --- AKHIR TAMBAHAN VARIABEL ---

        # Simulasi database blockchain untuk menyimpan hash gambar yang terdaftar
        # Kunci: hash SHA256 gambar, Nilai: path file (untuk referensi, di dunia nyata bisa metadata lain)
        self.blockchain_registered_hashes = {} 
        
        self.setup_gui()
        
    def setup_gui(self):
        """Menyiapkan antarmuka pengguna"""
        # Judul aplikasi
        title_label = ctk.CTkLabel(
            self.root, 
            text="Alat Steganografi LSB", 
            font=ctk.CTkFont(size=24, weight="bold")
        )
        title_label.pack(pady=20)
        
        # Membuat tabbed interface
        self.tabview = ctk.CTkTabview(self.root, width=750, height=500)
        self.tabview.pack(padx=20, pady=10, fill="both", expand=True)
        
        # Tab untuk encoding (menyembunyikan pesan)
        self.tabview.add("Sembunyikan Pesan (Encode)")
        self.setup_encode_tab()
        
        # Tab untuk decoding (mengekstrak pesan)
        self.tabview.add("Ekstrak Pesan (Decode)")
        self.setup_decode_tab()

        # Tab baru untuk Verifikasi Blockchain
        self.tabview.add("Verifikasi Blockchain")
        self.setup_blockchain_verify_tab()
        
    def setup_encode_tab(self):
        """Menyiapkan tab untuk menyembunyikan pesan"""
        encode_frame = self.tabview.tab("Sembunyikan Pesan (Encode)")
        
        # Tombol untuk memilih gambar cover
        self.select_cover_btn = ctk.CTkButton(
            encode_frame,
            text="📁 Pilih Gambar Cover...",
            command=self.select_cover_image,
            font=ctk.CTkFont(size=14),
            height=40
        )
        self.select_cover_btn.pack(pady=15)
        
        # Label untuk menampilkan path gambar cover
        self.cover_path_label = ctk.CTkLabel(
            encode_frame,
            text="Belum ada gambar yang dipilih",
            font=ctk.CTkFont(size=12),
            text_color="gray"
        )
        self.cover_path_label.pack(pady=(0, 15))
        
        # Label untuk textbox pesan
        message_label = ctk.CTkLabel(
            encode_frame,
            text="Masukkan Pesan Rahasia:",
            font=ctk.CTkFont(size=14, weight="bold")
        )
        message_label.pack(pady=(0, 10))
        
        # Textbox untuk memasukkan pesan rahasia
        self.message_textbox = ctk.CTkTextbox(
            encode_frame,
            width=600,
            height=120, # Sedikit diubah tinggi untuk memberi ruang kunci
            font=ctk.CTkFont(size=12)
        )
        self.message_textbox.pack(pady=(0, 10)) # Sedikit diubah pady
        
        # --- TAMBAHAN INPUT KUNCI ENKRIPSI ---
        key_label_encode = ctk.CTkLabel(
            encode_frame,
            text="Masukkan Kunci Enkripsi (min. 16 karakter):",
            font=ctk.CTkFont(size=14, weight="bold")
        )
        key_label_encode.pack(pady=(10, 5))
        self.key_entry_encode = ctk.CTkEntry(
            encode_frame,
            width=600,
            font=ctk.CTkFont(size=12),
            textvariable=self.encryption_key,
            show="*"
        )
        self.key_entry_encode.pack(pady=(0, 20))
        # --- AKHIR TAMBAHAN INPUT KUNCI ---

        # Tombol untuk menyembunyikan pesan dan menyimpan
        self.encode_btn = ctk.CTkButton(
            encode_frame,
            text="🔒 Sembunyikan & Simpan...",
            command=self.hide_message_with_encryption, # <--- UBAH COMMAND INI
            font=ctk.CTkFont(size=14, weight="bold"),
            height=40,
            fg_color="green",
            hover_color="darkgreen"
        )
        self.encode_btn.pack(pady=10)
        
    def setup_decode_tab(self):
        """Menyiapkan tab untuk mengekstrak pesan"""
        decode_frame = self.tabview.tab("Ekstrak Pesan (Decode)")
        
        # Tombol untuk memilih gambar yang berisi pesan rahasia
        self.select_secret_btn = ctk.CTkButton(
            decode_frame,
            text="📁 Pilih Gambar Rahasia...",
            command=self.select_secret_image,
            font=ctk.CTkFont(size=14),
            height=40
        )
        self.select_secret_btn.pack(pady=15)
        
        # Label untuk menampilkan path gambar rahasia
        self.secret_path_label = ctk.CTkLabel(
            decode_frame,
            text="Belum ada gambar yang dipilih",
            font=ctk.CTkFont(size=12),
            text_color="gray"
        )
        self.secret_path_label.pack(pady=(0, 15))
        
        # --- TAMBAHAN INPUT KUNCI DEKRIPSI ---
        key_label_decode = ctk.CTkLabel(
            decode_frame,
            text="Masukkan Kunci Dekripsi:",
            font=ctk.CTkFont(size=14, weight="bold")
        )
        key_label_decode.pack(pady=(10, 5))
        self.key_entry_decode = ctk.CTkEntry(
            decode_frame,
            width=600,
            font=ctk.CTkFont(size=12),
            show="*"
        )
        self.key_entry_decode.pack(pady=(0, 20))
        # --- AKHIR TAMBAHAN INPUT KUNCI ---

        # Tombol untuk mengekstrak pesan
        self.decode_btn = ctk.CTkButton(
            decode_frame,
            text="🔓 Ekstrak Pesan Sekarang",
            command=self.extract_message_with_decryption, # <--- UBAH COMMAND INI
            font=ctk.CTkFont(size=14, weight="bold"),
            height=40,
            fg_color="orange",
            hover_color="darkorange"
        )
        self.decode_btn.pack(pady=10)
        
        # Label untuk hasil ekstraksi
        result_label = ctk.CTkLabel(
            decode_frame,
            text="Hasil Ekstraksi Pesan:",
            font=ctk.CTkFont(size=14, weight="bold")
        )
        result_label.pack(pady=(20, 10))
        
        # Textbox untuk menampilkan hasil ekstraksi (read-only)
        self.result_textbox = ctk.CTkTextbox(
            decode_frame,
            width=600,
            height=120, # Sedikit diubah tinggi
            font=ctk.CTkFont(size=12),
            state="disabled"
        )
        self.result_textbox.pack(pady=(0, 20))

    def setup_blockchain_verify_tab(self):
        """Menyiapkan tab untuk verifikasi gambar di blockchain."""
        verify_frame = self.tabview.tab("Verifikasi Blockchain")

        # Tombol untuk memilih gambar yang akan diverifikasi
        self.select_verify_btn = ctk.CTkButton(
            verify_frame,
            text="⬆️ Unggah Gambar untuk Verifikasi...",
            command=self.select_image_for_verification,
            font=ctk.CTkFont(size=14),
            height=40
        )
        self.select_verify_btn.pack(pady=15)

        # Label untuk menampilkan path gambar yang akan diverifikasi
        self.verify_path_label = ctk.CTkLabel(
            verify_frame,
            text="Belum ada gambar yang dipilih untuk verifikasi",
            font=ctk.CTkFont(size=12),
            text_color="gray"
        )
        self.verify_path_label.pack(pady=(0, 15))

        # Tombol untuk memulai verifikasi
        self.start_verify_btn = ctk.CTkButton(
            verify_frame,
            text="✅ Verifikasi di Blockchain",
            command=self.verify_image_on_blockchain,
            font=ctk.CTkFont(size=14, weight="bold"),
            height=40,
            fg_color="blue",
            hover_color="darkblue"
        )
        self.start_verify_btn.pack(pady=10)

        # Label untuk hasil verifikasi (menggunakan CTkLabel agar mudah ganti warna)
        self.verify_status_label = ctk.CTkLabel(
            verify_frame,
            text="Pilih gambar untuk memulai verifikasi.",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="gray"
        )
        self.verify_status_label.pack(pady=(20, 10))
            
    def select_cover_image(self):
        """Fungsi untuk memilih gambar cover"""
        file_path = filedialog.askopenfilename(
            title="Pilih Gambar Cover",
            filetypes=[
                ("PNG files", "*.png"),
                ("JPEG files", "*.jpg"),
                ("All images", "*.png *.jpg *.jpeg")
            ]
        )
        
        if file_path:
            self.cover_image_path = file_path
            # Tampilkan nama file (bukan path lengkap)
            filename = os.path.basename(file_path)
            self.cover_path_label.configure(
                text=f"📷 {filename}", 
                text_color="white"
            )
            
    def select_secret_image(self):
        """Fungsi untuk memilih gambar yang berisi pesan rahasia"""
        file_path = filedialog.askopenfilename(
            title="Pilih Gambar Rahasia",
            filetypes=[
                ("PNG files", "*.png"),
                ("JPEG files", "*.jpg"),
                ("All images", "*.png *.jpg *.jpeg")
            ]
        )
        
        if file_path:
            self.secret_image_path = file_path
            filename = os.path.basename(file_path)
            self.secret_path_label.configure(
                text=f"📷 {filename}",
                text_color="white"
            )

    def select_image_for_verification(self):
        """Fungsi untuk memilih gambar yang akan diverifikasi di blockchain."""
        file_path = filedialog.askopenfilename(
            title="Pilih Gambar untuk Verifikasi",
            filetypes=[
                ("PNG files", "*.png"),
                ("JPEG files", "*.jpg"),
                ("All images", "*.png *.jpg *.jpeg")
            ]
        )
        
        if file_path:
            self.verify_image_path = file_path
            filename = os.path.basename(file_path)
            self.verify_path_label.configure(
                text=f"📷 {filename}",
                text_color="white"
            )
            # Reset status verifikasi sebelumnya
            self.verify_status_label.configure(
                text="Pilih 'Verifikasi di Blockchain' untuk memeriksa gambar ini.", 
                text_color="gray"
            )
            
    # --- FUNGSI KRIPTOGRAFI ---
    def encrypt_message(self, message_bytes, key_str):
        """
        Mengenkripsi pesan (dalam bentuk bytes) menggunakan AES-256 (mode CBC).
        Key_str akan di-hash menjadi kunci AES yang valid.
        Mengembalikan IV + Ciphertext.
        """
        try:
            # Menggunakan SHA256 dari key_str untuk menghasilkan kunci AES yang deterministik
            # AES-256 memerlukan kunci 32 byte.
            key_hash = sha256(key_str.encode('utf-8')).digest()[:32]

            cipher = AES.new(key_hash, AES.MODE_CBC)
            # Pesan harus di-padding agar panjangnya kelipatan dari ukuran blok AES (16 byte)
            ct_bytes = cipher.encrypt(pad(message_bytes, AES.block_size))
            return cipher.iv + ct_bytes # Menggabungkan IV dengan ciphertext
        except Exception as e:
            messagebox.showerror("Error Enkripsi", f"Gagal mengenkripsi pesan: {e}")
            return None

    def decrypt_message(self, enc_message_bytes, key_str):
        """
        Mendekripsi pesan (dalam bentuk IV + Ciphertext bytes) menggunakan AES-256 (mode CBC).
        Key_str akan di-hash menjadi kunci AES yang valid.
        Mengembalikan plaintext (dalam bentuk bytes).
        """
        try:
            key_hash = sha256(key_str.encode('utf-8')).digest()[:32]

            # IV adalah 16 byte pertama dari enc_message_bytes
            iv = enc_message_bytes[:AES.block_size]
            ciphertext = enc_message_bytes[AES.block_size:]

            cipher = AES.new(key_hash, AES.MODE_CBC, iv=iv)
            pt_bytes = unpad(cipher.decrypt(ciphertext), AES.block_size)
            return pt_bytes # Mengembalikan dalam bentuk bytes
        except Exception as e:
            messagebox.showerror("Error Dekripsi", f"Gagal mendekripsi pesan. Pastikan kunci dan gambar benar. Error: {e}")
            return None

    def encode_message_to_image(self, image_path, secret_message_bytes): # <--- UBAH PARAMETER INI
        """
        Fungsi inti untuk menyembunyikan pesan (dalam bytes) ke dalam gambar
        menggunakan teknik LSB (Least Significant Bit).
        Menggunakan prefix 4 byte untuk panjang pesan.
        """
        try:
            # Buka gambar
            img = Image.open(image_path)
            img = img.convert('RGB')  # Pastikan dalam format RGB
            
            # --- UBAH LOGIKA PESAN ---
            # Tambahkan panjang pesan sebagai 4 byte pertama dari secret_message_bytes
            message_with_length_prefix = len(secret_message_bytes).to_bytes(4, 'big') + secret_message_bytes
            
            # Konversi semua byte (prefix + pesan terenkripsi) ke string binary
            binary_message = ''.join(format(byte, '08b') for byte in message_with_length_prefix)
            # --- AKHIR UBAH LOGIKA PESAN ---
            
            # Dapatkan data pixel
            pixels = list(img.getdata())
            
            # Cek apakah gambar cukup besar untuk menyimpan pesan
            if len(binary_message) > len(pixels) * 3:
                raise ValueError("Pesan terlalu panjang untuk gambar ini!")
            
            # Proses encoding
            pixel_index = 0
            bit_index = 0
            
            new_pixels = []
            
            for pixel in pixels:
                r, g, b = pixel
                new_pixel = [r, g, b]
                
                # Modifikasi LSB untuk setiap komponen warna (R, G, B)
                for color_index in range(3):
                    if bit_index < len(binary_message):
                        # Dapatkan bit pesan saat ini
                        message_bit = int(binary_message[bit_index])
                        
                        # Modifikasi LSB
                        new_pixel[color_index] = (new_pixel[color_index] & 0xFE) | message_bit
                        
                        bit_index += 1
                
                new_pixels.append(tuple(new_pixel))
                pixel_index += 1
                
                # Jika semua bit pesan sudah disimpan, salin sisa pixel
                if bit_index >= len(binary_message):
                    new_pixels.extend(pixels[pixel_index:])
                    break
            
            # Buat gambar baru dengan pixel yang sudah dimodifikasi
            new_img = Image.new('RGB', img.size)
            new_img.putdata(new_pixels)
            
            return new_img
            
        except Exception as e:
            raise Exception(f"Error saat encoding: {str(e)}")
            
    def decode_message_from_image(self, image_path):
        """
        Fungsi inti untuk mengekstrak pesan (dalam bytes) dari gambar.
        Akan membaca prefix 4 byte untuk panjang pesan.
        """
        try:
            # Buka gambar
            img = Image.open(image_path)
            img = img.convert('RGB')
            
            # Dapatkan data pixel
            pixels = list(img.getdata())
            
            # Ekstrak bit dari LSB setiap komponen warna
            extracted_bits = ""
            
            for pixel in pixels:
                r, g, b = pixel
                
                # Ekstrak LSB dari setiap komponen warna
                extracted_bits += str(r & 1)
                extracted_bits += str(g & 1)
                extracted_bits += str(b & 1)
            
            # --- UBAH LOGIKA PESAN ---
            # Pastikan ada cukup bit untuk panjang pesan (4 byte = 32 bit)
            if len(extracted_bits) < 32:
                raise ValueError("Gambar tidak mengandung pesan tersembunyi yang valid (panjang prefix tidak ditemukan).")

            # Ekstrak 4 byte pertama untuk mendapatkan panjang pesan
            length_bits = extracted_bits[:32]
            message_length = int(length_bits, 2)

            # Hitung total bit yang harus diekstrak (panjang prefix + pesan terenkripsi)
            total_message_bits = 32 + (message_length * 8)

            # Cek apakah ada cukup bit dalam gambar untuk panjang pesan yang diekspektasikan
            if len(extracted_bits) < total_message_bits:
                raise ValueError("Pesan tersembunyi terpotong atau rusak. Panjang pesan yang terdeteksi tidak sesuai.")

            # Ekstrak pesan terenkripsi (dalam bentuk binary string)
            encrypted_message_binary = extracted_bits[32:total_message_bits]
            
            # Konversi binary string kembali ke bytes
            byte_array = bytearray()
            for i in range(0, len(encrypted_message_binary), 8):
                byte = int(encrypted_message_binary[i:i+8], 2)
                byte_array.append(byte)

            return bytes(byte_array) # Mengembalikan dalam bentuk bytes
            # --- AKHIR UBAH LOGIKA PESAN ---
            
        except Exception as e:
            raise Exception(f"Error saat decoding: {str(e)}")
            
    # --- HANDLER BARU UNTUK ENKRIPSI DAN STEGANOGRAFI ---
    def hide_message_with_encryption(self): # <--- NAMA FUNGSI BARU
        """Handler untuk tombol encode: mengenkripsi dan menyembunyikan pesan"""
        # Validasi input
        if not self.cover_image_path:
            messagebox.showerror("Error", "Silakan pilih gambar cover terlebih dahulu!")
            return
            
        message_str = self.message_textbox.get("1.0", "end-1c").strip()
        if not message_str:
            messagebox.showerror("Error", "Silakan masukkan pesan rahasia!")
            return

        encryption_key = self.key_entry_encode.get().strip()
        if not encryption_key or len(encryption_key) < 16: # AES-256 sebaiknya pakai kunci yang cukup panjang
            messagebox.showerror("Error", "Kunci enkripsi harus diisi dan minimal 16 karakter.")
            return
            
        try:
            # 1. Enkripsi pesan (string diubah ke bytes sebelum dienkripsi)
            encrypted_bytes = self.encrypt_message(message_str.encode('utf-8'), encryption_key)
            if encrypted_bytes is None: # Cek jika enkripsi gagal
                return

            # 2. Proses encoding (menyembunyikan bytes terenkripsi)
            encoded_image = self.encode_message_to_image(self.cover_image_path, encrypted_bytes)
            
            # Dialog untuk menyimpan file
            save_path = filedialog.asksaveasfilename(
                title="Simpan Gambar dengan Pesan Tersembunyi",
                defaultextension=".png",
                filetypes=[("PNG files", "*.png")]
            )
            
            if save_path:
                # Simpan gambar
                encoded_image.save(save_path, "PNG")
                messagebox.showinfo(
                    "Berhasil!", 
                    f"Pesan berhasil disembunyikan dan disimpan ke:\n{save_path}"
                )
                
                # --- Otomatis daftarkan gambar ke "blockchain" (simulasi) ---
                self.register_image_on_blockchain(save_path)
                # --------------------------------------------------------
                
                # Reset form
                self.message_textbox.delete("1.0", "end")
                self.key_entry_encode.delete(0, "end") # Reset kunci juga
                self.cover_path_label.configure(text="Belum ada gambar yang dipilih", text_color="gray")
                self.cover_image_path = "" # Reset path cover image
                
        except Exception as e:
            messagebox.showerror("Error", str(e))
            
    # --- HANDLER BARU UNTUK DEKRIPSI DAN EKSTRAKSI STEGANOGRAFI ---
    def extract_message_with_decryption(self): # <--- NAMA FUNGSI BARU
        """Handler untuk tombol decode: mengekstrak dan mendekripsi pesan"""
        # Validasi input
        if not self.secret_image_path:
            messagebox.showerror("Error", "Silakan pilih gambar rahasia terlebih dahulu!")
            return
            
        decryption_key = self.key_entry_decode.get().strip()
        if not decryption_key:
            messagebox.showerror("Error", "Kunci dekripsi tidak boleh kosong.")
            return

        try:
            # 1. Proses decoding (mengekstrak bytes terenkripsi)
            extracted_encrypted_bytes = self.decode_message_from_image(self.secret_image_path)
            if extracted_encrypted_bytes is None: # Jika tidak ada pesan atau error saat ekstraksi LSB
                 self.result_textbox.configure(state="normal")
                 self.result_textbox.delete("1.0", "end")
                 self.result_textbox.insert("1.0", "Tidak ditemukan pesan tersembunyi atau gambar rusak.")
                 self.result_textbox.configure(state="disabled")
                 messagebox.showerror("Error", "Tidak ditemukan pesan tersembunyi atau gambar rusak.")
                 return

            # 2. Dekripsi pesan
            decrypted_message_bytes = self.decrypt_message(extracted_encrypted_bytes, decryption_key)
            if decrypted_message_bytes is None: # Cek jika dekripsi gagal
                self.result_textbox.configure(state="normal")
                self.result_textbox.delete("1.0", "end")
                self.result_textbox.insert("1.0", "Gagal mendekripsi. Pastikan kunci dan gambar benar.")
                self.result_textbox.configure(state="disabled")
                return

            decoded_message = decrypted_message_bytes.decode('utf-8') # Decode bytes ke string untuk tampilan

            # Tampilkan hasil di textbox
            self.result_textbox.configure(state="normal")
            self.result_textbox.delete("1.0", "end")
            self.result_textbox.insert("1.0", decoded_message)
            self.result_textbox.configure(state="disabled")
            
            messagebox.showinfo("Berhasil!", "Pesan berhasil diekstrak dan didekripsi!")
            
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def calculate_image_hash(self, image_path):
        """Menghitung hash SHA256 dari sebuah file gambar."""
        try:
            # Gunakan 'rb' untuk membaca file dalam mode biner
            with open(image_path, 'rb') as f:
                bytes_data = f.read()
                readable_hash = hashlib.sha256(bytes_data).hexdigest()
                return readable_hash
        except FileNotFoundError:
            raise Exception("File gambar tidak ditemukan.")
        except Exception as e:
            raise Exception(f"Gagal menghitung hash gambar: {e}")

    def register_image_on_blockchain(self, image_path):
        """
        Fungsi simulasi untuk 'mendaftarkan' hash gambar ke blockchain.
        Dalam aplikasi nyata, ini akan menjadi transaksi ke smart contract di jaringan blockchain.
        """
        try:
            img_hash = self.calculate_image_hash(image_path)
            self.blockchain_registered_hashes[img_hash] = image_path # Simpan hash dan path (metadata)
            print(f"Gambar terdaftar ke 'blockchain' (simulasi): {os.path.basename(image_path)} dengan hash {img_hash[:10]}...")
        except Exception as e:
            messagebox.showwarning(
                "Pendaftaran Blockchain Gagal (Simulasi)", 
                f"Tidak dapat mendaftarkan gambar ke blockchain: {e}\n"
                "Ini hanyalah simulasi, di dunia nyata mungkin perlu koneksi internet atau biaya transaksi."
            )

    def verify_image_on_blockchain(self):
        """
        Handler untuk tombol verifikasi di blockchain.
        Akan memeriksa apakah gambar terdaftar dan apakah integritasnya terjaga.
        """
        if not self.verify_image_path:
            messagebox.showerror("Error", "Silakan pilih gambar untuk diverifikasi terlebih dahulu!")
            self.verify_status_label.configure(
                text="Error: Silakan pilih gambar terlebih dahulu!", 
                text_color="red"
            )
            return

        self.verify_status_label.configure(
            text="Status Verifikasi: Memulai verifikasi di blockchain...",
            text_color="yellow" # Warna sementara saat proses
        )
        self.root.update_idletasks() # Perbarui GUI segera untuk menampilkan status loading

        try:
            current_image_hash = self.calculate_image_hash(self.verify_image_path)
            
            if current_image_hash in self.blockchain_registered_hashes:
                # Gambar terdaftar di blockchain (simulasi)
                status_text = "✅ Verifikasi Berhasil: Gambar ini terdaftar di blockchain dan integritasnya utuh."
                status_color = "green"
            else:
                # Gambar tidak terdaftar di blockchain (simulasi)
                status_text = "❌ Error: Gambar ini TIDAK terdaftar di blockchain kami. Tidak dapat memverifikasi keaslian."
                status_color = "red"
                
            self.verify_status_label.configure(
                text=status_text,
                text_color=status_color
            )
            messagebox.showinfo("Verifikasi Selesai", "Proses verifikasi gambar telah selesai.")

        except Exception as e:
            self.verify_status_label.configure(
                text=f"Error Verifikasi: {str(e)}",
                text_color="red"
            )
            messagebox.showerror("Error Verifikasi", str(e))
            
    def run(self):
        """Menjalankan aplikasi"""
        self.root.mainloop()

# Blok utama program
if __name__ == "__main__":
    app = SteganographyApp()
    app.run()