# 🖼️ Aplikasi Steganografi GUI dengan Python

Sebuah aplikasi desktop sederhana yang dibangun dengan Python untuk menyembunyikan pesan teks rahasia di dalam sebuah gambar menggunakan metode **Least Significant Bit (LSB)**. Proyek ini adalah tugas untuk mata kuliah Kriptografi.

![Screenshot Aplikasi](screenshots-aplikasi.jpeg)

---

## ✨ Fitur Utama

Aplikasi ini dirancang dengan antarmuka yang bersih dan fungsional, terbagi menjadi dua fungsi utama:

### **Sembunyikan Pesan (Encode)**
* **Pilih Gambar Cover:** Membuka dialog file untuk memilih gambar default `.png` yang akan digunakan sebagai media pembawa pesan. bukan hanya `.png`, bisa juga dengan format lain seperti `.jpg`, `.jpeg`.
* **Input Pesan Multi-baris:** Kotak teks yang luas untuk menulis pesan rahasia dengan nyaman.
* **Proses Penyembunyian Cerdas:** Menggunakan metode LSB untuk menyisipkan pesan ke dalam piksel gambar tanpa merusak kualitas visual.
* **Simpan Hasil:** Membuka dialog "Save As" agar pengguna bisa menyimpan gambar baru yang sudah berisi rahasia di lokasi yang diinginkan.

### **Ekstrak Pesan (Decode)**
* **Pilih Gambar Rahasia:** Membuka dialog file untuk memilih gambar yang diduga berisi pesan tersembunyi.
* **Ekstraksi Sekali Klik:** Tombol sederhana untuk memulai proses pencarian dan ekstraksi pesan.
* **Tampilkan Hasil:** Menampilkan teks rahasia yang berhasil ditemukan di dalam kotak hasil yang *read-only*.
* **Penanganan Eror:** Memberikan notifikasi yang jelas jika tidak ada pesan yang ditemukan atau jika terjadi kesalahan lain.

---

## 🚀 Teknologi yang Digunakan

Proyek ini dibangun menggunakan teknologi Python yang populer dan andal:

* **Bahasa Pemrograman**: Python 3
* **Library GUI**: CustomTkinter
* **Manipulasi Gambar**: Pillow (PIL Fork)

---

## 🛠️ Cara Instalasi & Setup

Ikuti langkah-langkah ini untuk menjalankan proyek di komputer lokal.

1.  **Prasyarat**
    Pastikan Python 3 dan `pip` sudah terinstal di sistem operasi.

2.  **Clone repository ini:**
    ```bash
    git clone https://github.com/Zivalez/steganografi-dengan-blockchain-GUI.git
    cd steganografi-dengan-blockchain-GUI
    ```

3.  **Install semua dependency yang dibutuhkan:**
    Aplikasi ini memerlukan beberapa library. Buka terminal atau command prompt dan jalankan perintah ini:
    ```bash
    pip install customtkinter Pillow
    Pip install pycryptodome
    ```

4.  **Jalankan aplikasi:**
    Setelah semua dependensi terpasang, jalankan skrip utama Python.
    ```bash
    python steganografi_with_verification.py
    ```

5.  **Aplikasi Siap Digunakan!**
    Jendela aplikasi akan langsung muncul dan siap untuk menyembunyikan rahasia pertama.