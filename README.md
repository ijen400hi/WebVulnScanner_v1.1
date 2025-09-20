# WebVulnScanner v1.1

Script Python canggih untuk scanning kerentanan keamanan web seperti SQL Injection, XSS, CSRF, Open Redirects, Directory Traversal, SSRF, RCE, dan banyak lagi.

## Fitur Baru di Versi 1.1
- **Enhanced Security Scanning**: Peningkatan akurasi deteksi dengan payload yang lebih komprehensif
- **Security Headers Check**: Pemeriksaan header keamanan penting (HSTS, CSP, X-Frame-Options, dll)
- **Information Disclosure Detection**: Deteksi kebocoran informasi sensitif
- **File Upload Vulnerability Testing**: Pemeriksaan kerentanan upload file
- **Multiple Export Formats**: Export hasil scan dalam format HTML, JSON, dan CSV
- **Command Line Interface**: Mendukung argument parsing untuk mode batch
- **Session Management**: User agent rotation dan session handling yang lebih baik
- **Enhanced Error Handling**: Penanganan error yang lebih robust
- **Load Previous Results**: Kemampuan memuat hasil scan sebelumnya
- **Custom Scan Configuration**: Konfigurasi scan yang dapat disesuaikan
- **Improved User Experience**: Interface yang lebih user-friendly dengan menu yang lebih lengkap
- **Better Detection Logic**: Logika deteksi yang lebih cerdas dan akurat

## Fitur Utama
- **Menu Interaktif**: Pilih jenis scan yang diinginkan atau lakukan full scan.
- **Multi-threading**: Full scan berjalan paralel untuk efisiensi.
- **Progress Bar**: Tampilkan kemajuan scan dengan tqdm.
- **Report HTML**: Hasil scan disimpan dalam file HTML yang mudah dibaca.
- **Desain Canggih**: Menggunakan warna untuk output terminal.

## Instalasi

### Persyaratan Sistem
- Python 3.x
- Windows/Linux/Mac

### Langkah Instalasi
1. **Clone Repository** (jika di GitHub):
   ```
   git clone https://github.com/ijen400hi/WebVulnScanner_v1.1.git
   cd WebVulnScanner_v1.1
   ```

2. **Install Dependencies**:
   Jalankan perintah berikut di terminal:
   ```
   pip install requests beautifulsoup4 colorama tqdm
   ```

   Atau install satu per satu:
   ```
   pip install requests
   pip install beautifulsoup4
   pip install colorama
   pip install tqdm
   ```

## Cara Menjalankan

1. **Jalankan Script**:
   ```
   python WebVulnScanner_v1.1.py
   ```

2. **Masukkan URL Website**:
   Masukkan URL target, contoh: `https://example.com`

3. **Pilih Jenis Scan**:
   - 1. SQL Injection (Enhanced)
   - 2. XSS (Enhanced)
   - 3. CSRF (Enhanced)
   - 4. Open Redirects
   - 5. Directory Traversal
   - 6. SSRF
   - 7. RCE
   - 8. Security Headers Check
   - 9. Information Disclosure
   - 10. File Upload Vulnerabilities
   - 11. Full Scan (All) - Rekomendasi untuk scan lengkap
   - 12. Custom Scan Configuration
   - 13. Export Results
   - 14. Load Previous Results
   - 15. Keluar

4. **Lihat Hasil**:
   - Hasil individual ditampilkan di terminal.
   - Untuk full scan, report HTML disimpan sebagai `scan_report.html`.

## Contoh Penggunaan

```
python WebVulnScanner.py
Masukkan URL website (contoh: http://example.com): https://targetsite.com
Pilih jenis scan:
1. SQL Injection
...
8. Full Scan (All)
Masukkan pilihan (1-15): 8
```

Script akan menjalankan semua scan secara paralel dan menghasilkan report.

## Catatan
- Script ini untuk tujuan edukasi dan testing pada website yang Anda miliki izinnya.
- Jangan gunakan untuk aktivitas ilegal.
- Hasil scan mungkin tidak 100% akurat, tergantung pada implementasi website target.

## Kontribusi
Silakan buat issue atau pull request jika ada saran perbaikan.

BY 400HI
