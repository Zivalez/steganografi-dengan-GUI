import customtkinter as ctk
from tkinter import filedialog, messagebox
from PIL import Image
import os
import hashlib # Untuk menghitung hash gambar

class SteganographyApp:
    def __init__(self):
        # Konfigurasi tema CustomTkinter
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # Inisialisasi jendela utama
        self.root = ctk.CTk()
        self.root.title("Alat Steganografi LSB")
        self.root.geometry("800x600")
        self.root.resizable(True, True)
        
        # Variabel untuk menyimpan path file
        self.cover_image_path = ""
        self.secret_image_path = ""
        self.verify_image_path = "" # Path untuk gambar yang akan diverifikasi
        
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
            height=200,
            font=ctk.CTkFont(size=12)
        )
        self.message_textbox.pack(pady=(0, 20))
        
        # Tombol untuk menyembunyikan pesan dan menyimpan
        self.encode_btn = ctk.CTkButton(
            encode_frame,
            text="🔒 Sembunyikan & Simpan...",
            command=self.encode_message,
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
        
        # Tombol untuk mengekstrak pesan
        self.decode_btn = ctk.CTkButton(
            decode_frame,
            text="🔓 Ekstrak Pesan Sekarang",
            command=self.decode_message,
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
            height=200,
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
            
    def encode_message_to_image(self, image_path, secret_message):
        """
        Fungsi inti untuk menyembunyikan pesan ke dalam gambar
        menggunakan teknik LSB (Least Significant Bit)
        """
        try:
            # Buka gambar
            img = Image.open(image_path)
            img = img.convert('RGB')  # Pastikan dalam format RGB
            
            # Tambahkan delimiter untuk menandai akhir pesan
            delimiter = "###END###"
            message_with_delimiter = secret_message + delimiter
            
            # Konversi pesan ke binary
            binary_message = ''.join(format(ord(char), '08b') for char in message_with_delimiter)
            
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
        Fungsi inti untuk mengekstrak pesan dari gambar.
        Akan melempar ValueError jika delimiter tidak ditemukan (pesan rusak/tidak ada).
        """
        try:
            # Buka gambar
            img = Image.open(image_path)
            img = img.convert('RGB')
            
            # Dapatkan data pixel
            pixels = list(img.getdata())
            
            # Ekstrak bit dari LSB setiap komponen warna
            binary_message = ""
            
            for pixel in pixels:
                r, g, b = pixel
                
                # Ekstrak LSB dari setiap komponen warna
                binary_message += str(r & 1)
                binary_message += str(g & 1)
                binary_message += str(b & 1)
            
            # Konversi binary ke string
            message = ""
            delimiter = "###END###"
            
            # Proses setiap 8 bit sebagai satu karakter
            for i in range(0, len(binary_message), 8):
                byte = binary_message[i:i+8]
                if len(byte) == 8:
                    char = chr(int(byte, 2))
                    message += char
                    
                    # Cek apakah sudah menemukan delimiter
                    if message.endswith(delimiter):
                        # Hapus delimiter dari pesan
                        message = message[:-len(delimiter)]
                        return message
            
            # Jika tidak menemukan delimiter setelah memproses seluruh gambar
            raise ValueError("Tidak ditemukan pesan rahasia dalam gambar ini! Mungkin rusak atau tidak ada pesan.")
            
        except Exception as e:
            # Tangkap semua exception dan lempar ulang sebagai Exception kustom
            # agar lebih mudah dibedakan di pemanggil
            raise Exception(f"Error saat decoding: {str(e)}")
            
    def encode_message(self):
        """Handler untuk tombol encode"""
        # Validasi input
        if not self.cover_image_path:
            messagebox.showerror("Error", "Silakan pilih gambar cover terlebih dahulu!")
            return
            
        message = self.message_textbox.get("1.0", "end-1c").strip()
        if not message:
            messagebox.showerror("Error", "Silakan masukkan pesan rahasia!")
            return
            
        try:
            # Proses encoding
            encoded_image = self.encode_message_to_image(self.cover_image_path, message)
            
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
                self.cover_path_label.configure(text="Belum ada gambar yang dipilih", text_color="gray")
                self.cover_image_path = "" # Reset path cover image
                
        except Exception as e:
            messagebox.showerror("Error", str(e))
            
    def decode_message(self):
        """Handler untuk tombol decode"""
        # Validasi input
        if not self.secret_image_path:
            messagebox.showerror("Error", "Silakan pilih gambar rahasia terlebih dahulu!")
            return
            
        try:
            # Proses decoding
            decoded_message = self.decode_message_from_image(self.secret_image_path)
            
            # Tampilkan hasil di textbox
            self.result_textbox.configure(state="normal")
            self.result_textbox.delete("1.0", "end")
            self.result_textbox.insert("1.0", decoded_message)
            self.result_textbox.configure(state="disabled")
            
            messagebox.showinfo("Berhasil!", "Pesan berhasil diekstrak!")
            
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
        Akan memeriksa apakah gambar terdaftar dan apakah integritas pesannya terjaga.
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
                # original_path_from_blockchain = self.blockchain_registered_hashes[current_image_hash]
                
                # Sekarang, coba ekstrak pesan untuk memeriksa integritasnya
                try:
                    self.decode_message_from_image(self.verify_image_path)
                    status_text = "✅ Verifikasi Berhasil: Gambar utuh dan pesan tersembunyi baik!"
                    status_color = "green"
                except ValueError: # Ini akan ditangkap jika delimiter tidak ditemukan (pesan rusak/tidak ada)
                    status_text = "❌ Verifikasi Gagal: Gambar terdaftar, tetapi pesan tersembunyi rusak atau tidak ditemukan."
                    status_color = "red"
                except Exception as e: # Tangani error lain saat proses decode
                    status_text = f"❗ Verifikasi Gagal: Gambar terdaftar, namun error saat membaca pesan. ({e})"
                    status_color = "red"
                    
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