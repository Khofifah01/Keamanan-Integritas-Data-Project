# Layanan Kriptografi API

Project ini merupakan implementasi layanan kriptografi berbasis API menggunakan FastAPI yang berfungsi sebagai trusted authority server untuk mendukung keamanan dan integritas pertukaran data.

Sistem menyediakan fitur login dan secure session menggunakan token, penyimpanan public key, verifikasi tanda tangan digital pada pesan dan file PDF menggunakan Ed25519, serta pengiriman pesan aman dengan enkripsi AES-256. Pengujian dilakukan melalui endpoint API menggunakan Swagger UI untuk memastikan setiap fitur berjalan sesuai kebutuhan keamanan sistem.

## Tools

* Python
* FastAPI
* Uvicorn
* Cryptography
* Ed25519
* AES-256 (CBC)
* REST API
* Swagger UI
