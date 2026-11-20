# Rencana — Build 31: WebSocket (RFC 6455)

Sumber: RFC 6455 (teks penuh di `../websocket-ref/rfc6455.txt`).
Wasit: pustaka `websockets` 17.4 (venv `../websocket-ref/venv`) —
interop HIDUP dua arah lewat socket sungguhan, bukan sekadar
contoh statis. Jangkar emas statis: contoh frame §5.7 dan
handshake contoh §1.2/§1.3 di dalam RFC itu sendiri.

## Irisan

- [x] Irisan 1 — Handshake + codec frame: Sec-WebSocket-Accept
      (SHA-1+base64 per §4), validasi handshake dua sisi, tulis/
      baca frame (panjang 7/16/64-bit bentuk terpendek), masking
      XOR. Uji: jangkar handshake RFC + SEMUA contoh §5.7
      byte-exact dua arah (contoh bertopeng memakai kunci tetap
      RFC, jadi serialisasinya pun byte-exact).
- [x] Irisan 2 — Mesin keadaan koneksi: peran masking (server
      menuntut bertopeng, klien menuntut tidak), fragmentasi +
      rakit ulang, kontrol menyela di tengah fragmen, ping ->
      pong otomatis, handshake tutup bergema, kode tutup sah.
      Uji di transport memori: semua pelanggaran klasik ditolak
      (RSV, kontrol terfragmentasi/>125, lanjutan yatim, pesan
      baru di tengah fragmen, UTF-8 rusak -> 1007, topeng salah
      peran).
- [x] Irisan 3 — Interop hidup melawan `websockets`: server-ku
      x klien mereka, server mereka x klien-ku — echo teks/biner
      100 KB, kirim terfragmentasi, ping/pong, kode tutup
      menyebar. Plus server x klien milik sendiri di socket asli.

## Keputusan lingkup

- Ekstensi (permessage-deflate dsb.) di luar lingkup: bit RSV
  bukan nol ditolak, sesuai RFC tanpa ekstensi yang dinegosiasi.
- Panjang bukan-terpendek DITERIMA saat membaca (RFC mewajibkan
  bentuk terpendek pada PENGIRIM — 5.2 — tanpa memerintahkan
  penolakan); penulis selalu memancarkan bentuk terpendek.
- TLS (wss://) di luar lingkup: transport-nya socket TCP polos;
  Koneksi hanya menuntut objek transport kirim/ambil.

## Pagar selesai

- [x] Semua uji irisan 1–3 hijau.
- [x] README.md + CATATAN.md lengkap.
- [ ] Terbit di github.com/h0c0de/build-your-own-websocket-python
