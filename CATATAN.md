# Catatan — Build 31: WebSocket (RFC 6455)

## Irisan 1 — Handshake + codec frame (46 cek)

Jangkar emasnya di dalam RFC itu sendiri, jadi tak ada tebakan:
§1.2/§1.3 memberi pasangan kunci -> accept
(`dGhlIHNhbXBsZSBub25jZQ==` -> `s3pPLMBiTxaQ9kYGzzhZRbK+xOo=`),
dan §5.7 mencetak enam keluarga contoh frame sebagai hex.
Kelima contoh kecilnya (teks plain, teks bertopeng, fragmen,
ping, pong bertopeng) lolos urai + tulis-ulang byte-exact —
contoh bertopeng pun byte-exact karena RFC memakai kunci tetap
`37fa213d`. Dua contoh besar (256 byte, 64 KiB) dicocokkan
kepalanya persis dan isinya pola sendiri.

Keputusan yang dicatat terbuka: panjang bukan-terpendek
(mis. 5 ditulis dalam bentuk 16-bit) DITERIMA parser. RFC §5.2
berbunyi pengirim "MUST use the minimal number of bytes" —
kewajiban pengirim; tidak ada perintah menolak bagi penerima.
Penulis frame di sini selalu terpendek; parser permisif.
Ini juga perilaku pustaka wasitnya.

Header handshake diuraikan dengan penggabungan token koma —
`Connection: keep-alive, Upgrade` adalah bentuk yang benar-
benar datang dari klien nyata, dan validasi token-per-token
menangkapnya.

## Irisan 2 — Mesin keadaan (21 cek)

Diuji di transport memori berpasangan, tanpa socket: rakitan
fragmen, ping yang menyela di tengah fragmen (pong keluar
membawa muatan yang sama DAN rakitan tidak rusak — urutan yang
paling sering salah di implementasi pemula), gema tutup dengan
muatan identik, dan sembilan pelanggaran: tanpa topeng ke
server, bertopeng ke klien, lanjutan yatim, pesan baru di
tengah fragmen, UTF-8 rusak (kode 1007, bukan 1002), muatan
tutup 1 byte, kode semu 1005 muncul di kabel, alasan tutup
bukan UTF-8. Setiap pelanggaran juga memancarkan frame tutup
berkode benar ke lawan — terverifikasi dari byte mentahnya.

Satu bug uji tertangkap di irisan ini (bukan bug implementasi):
kotak masuk transport yang diperiksa terbalik arah — pengingat
bahwa di sistem berpasangan, "yang klien kirim" tinggal di
kotak masuk SERVER.

## Irisan 3 — Interop hidup (11 cek)

Melawan `websockets` 17.4 (API sync) di 127.0.0.1:

- **Server-ku x klien mereka:** echo teks dan biner 100 KB,
  ping mereka dijawab pong-ku (waiter mereka terpicu), close
  3000 + alasan menyebar dan thread serverku menutup bersih.
- **Server mereka x klien-ku:** echo dua arah, pesan
  terfragmentasi dari klienku terakit utuh di server mereka,
  ping-ku dibalas pong mereka, gema tutup 1000 kembali.
- **Lingkar penuh** server-ku x klien-ku di socket asli.

Tidak ada penyesuaian yang dibutuhkan untuk lolos — handshake
ku (yang tidak menawarkan ekstensi apa pun) diterima server
mereka apa adanya, dan validasi handshake-ku menerima bentuk
header klien mereka. Total build: 46 + 21 + 11 = **78 cek**.
