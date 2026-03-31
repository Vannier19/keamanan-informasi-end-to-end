# Sistem Komunikasi Terenkripsi End-to-End

## Pembuat Proyek

- **Stevan Einer Bonagabe** (18223028)
- **Sebastian Albern Nugroho** (18223074)

## Tentang Proyek Ini

Mata Kuliah: **II3230 - Keamanan Informasi**  
Tugas: **Kriptografi - End-to-End Encrypted Communication**

Proyek ini mengimplementasikan sistem pertukaran pesan yang aman antara Alice (pengirim) dan Bob (penerima) menggunakan kriptografi hybrid. Pesan dienkripsi menggunakan:

- **Enkripsi Simetris**: AES-256-GCM untuk enkripsi pesan
- **Enkripsi Asimetris**: RSA-2048 OAEP untuk membungkus kunci AES
- **Hash**: SHA-256 untuk integritas pesan
- **Digital Signature**: RSASSA-PSS untuk autentikasi pengirim

Kedua layanan Alice dan Bob berjalan di dalam container Docker terpisah dalam jaringan privat (172.20.0.0/16).

## Cara Menjalankan Program

### Prasyarat

- Docker Desktop/Engine versi 20.10+
- Docker Compose versi 1.29+

### Langkah-Langkah

**1. Buka terminal dan masuk ke folder proyek:**
```bash
cd "d:\Sems 6\security\tugas-kripto-e2e"
```

**2. Jalankan dengan Docker Compose:**
```bash
docker-compose up --build
```

Output yang akan muncul:
```
alice_sender  | [Alice] Layanan enkripsi berjalan di port 3000
bob_receiver  | [Bob] Layanan dekripsi berjalan di port 4000
```

**3. Buka terminal baru dan kirim pesan test:**
```bash
curl -X POST http://localhost:3000/send ^
  -H "Content-Type: application/json" ^
  -d "{\"message\": \"Halo Bob!\"}"
```

**4. Lihat log proses enkripsi dan dekripsi:**
```bash
docker-compose logs alice
docker-compose logs bob
```

**5. Untuk menghentikan program:**
Tekan `Ctrl+C` di terminal pertama, atau:
```bash
docker-compose down
```

### Menggunakan PowerShell (Windows)

```powershell
$body = @{message="Halo Bob dari PowerShell!"} | ConvertTo-Json
Invoke-WebRequest -Uri "http://localhost:3000/send" `
  -Method POST -ContentType "application/json" -Body $body
```

## Payload yang Dikirim

Alice mengirim payload JSON ke Bob berisi:
- `ciphertext` - pesan yang sudah dienkripsi
- `iv` - initialization vector untuk AES-GCM
- `auth_tag` - authentication tag dari AES-GCM
- `encrypted_key` - kunci AES yang sudah dibungkus RSA
- `hash` - SHA-256 hash dari plaintext
- `signature` - digital signature menggunakan RSASSA-PSS
- `source_ip` dan `destination_ip` - metadata jaringan

Semua data ditransmisikan dalam format Base64 untuk JSON compatibility.
	"source_ip": "172.20.0.10",
	"destination_ip": "172.20.0.20",
	"ciphertext": "<hasil enkripsi pesan dalam Base64>",
	"iv": "<initialization vector AES dalam Base64>",
	"auth_tag": "<authentication tag AES-GCM dalam Base64>",
	"encrypted_key": "<kunci AES yang dibungkus RSA dalam Base64>",
	"hash": "<hash SHA-256 plaintext dalam format hex>",
	"signature": "<tanda tangan digital RSASSA-PSS dalam Base64>",
	"hash_algorithm": "SHA256",
	"symmetric_algorithm": "AES256-GCM",
	"asymmetric_algorithm": "RSA2048"
}
```
