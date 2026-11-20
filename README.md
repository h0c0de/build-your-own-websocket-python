# Build Your Own — WebSocket

Protokol **WebSocket (RFC 6455)** dalam Python murni:
handshake pembuka HTTP Upgrade, codec frame biner, masking,
fragmentasi, dan mesin keadaan koneksi untuk **klien dan
server** — tanpa pustaka WebSocket apa pun. Dibuktikan
byte-exact dengan contoh resmi RFC §5.7, lalu **interop hidup
dua arah melawan pustaka `websockets`** lewat socket sungguhan:
server build ini melayani klien mereka, klien build ini
berbicara ke server mereka.

Ini build protokol *stateful* pertama seri ini — yang diuji
bukan hanya bentuk byte, melainkan perilaku percakapan.

## Isi

| Berkas | Isi |
|---|---|
| `websocketku.py` | Handshake (§4), frame (§5), masking, mesin keadaan `Koneksi`, transport socket |
| `uji_bersama.py` | Contoh resmi §5.7 + jangkar handshake sebagai konstanta, transport memori |
| `uji_irisan1.py` … `uji_irisan3.py` | Uji per irisan (irisan 3 perlu `websockets`) |

## Memakai

```python
import socket
from websocketku import terima_koneksi, sambung_ke

# Server (socket sudah accept):
kon = terima_koneksi(sock)
jenis, teks = kon.terima()          # ('teks', 'halo')
kon.kirim_teks(teks.upper())

# Klien:
kon = sambung_ke(sock, "127.0.0.1:8765", "/chat")
kon.kirim_teks("halo")
print(kon.terima())                 # ping dijawab otomatis
kon.tutup()
```

## Tiga hal yang menentukan

1. **Frame ≠ pesan.** Satu pesan aplikasi boleh dipecah jadi
   banyak frame (fragmen), dan frame kontrol boleh menyela *di
   tengah* pecahan itu. Parser yang mencampur keduanya akan
   merusak rakitan atau menelan ping — mesin keadaan terpisah
   yang menegakkan urutannya.
2. **Masking itu asimetris dan wajib.** Klien HARUS menutupi
   setiap frame dengan kunci acak baru; server DILARANG
   menutupi. Melanggar salah satu arah = kesalahan protokol
   1002, dan kedua arah diuji di sini.
3. **Tutup adalah handshake, bukan putus.** Yang menerima
   frame tutup membalas dengan muatan yang sama sebelum TCP
   ditutup; kode 1005/1006/1015 adalah nilai semu lokal yang
   tidak pernah boleh muncul di kabel.

## Kejujuran lingkup

Ekstensi (permessage-deflate) tidak dinegosiasikan — bit RSV
bukan nol ditolak. TLS di luar lingkup: transport-nya socket
TCP polos, dan `Koneksi` hanya menuntut objek berkirim/ambil.
Panjang bukan-terpendek *diterima* saat membaca: RFC §5.2
mewajibkannya pada pengirim tanpa memerintahkan penolakan —
penulis di sini selalu memancarkan bentuk terpendek.

## Lisensi

Kode: MIT. RFC 6455 © IETF Trust. `websockets` hanya wasit
uji, tidak disertakan.
