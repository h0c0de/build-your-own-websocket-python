"""Irisan 1 — handshake + codec frame melawan jangkar RFC 6455."""
import sys

sys.path.insert(0, ".")
sys.path.insert(0, "..")

from websocketku import (GalatHandshake, GalatProtokol, baca_frame,
                         hitung_terima, kunci_dari_handshake_klien,
                         permintaan_handshake, periksa_tanggapan_server,
                         tanggapan_handshake, terapkan_topeng,
                         tulis_frame, OP_BINER, OP_PING, OP_PONG, OP_TEKS)
from uji_bersama import (FRAME_FRAG_1, FRAME_FRAG_2, FRAME_PING,
                         FRAME_PONG_TOPENG, FRAME_TEKS_PLAIN,
                         FRAME_TEKS_TOPENG, KUNCI_CONTOH, KUNCI_TOPENG_RFC,
                         TERIMA_CONTOH)

lulus = 0


def cek(kondisi, pesan):
    global lulus
    assert kondisi, pesan
    lulus += 1


def cek_galat(fungsi, jenis, pesan):
    global lulus
    try:
        fungsi()
    except jenis:
        lulus += 1
        return
    raise AssertionError(f"tidak naik {jenis.__name__}: {pesan}")


# --- Handshake: jangkar emas RFC 1.2/1.3 --------------------------
cek(hitung_terima(KUNCI_CONTOH) == TERIMA_CONTOH,
    "Sec-WebSocket-Accept contoh RFC cocok")

permintaan = (
    "GET /chat HTTP/1.1\r\nHost: server.example.com\r\n"
    "Upgrade: websocket\r\nConnection: Upgrade\r\n"
    f"Sec-WebSocket-Key: {KUNCI_CONTOH}\r\n"
    "Origin: http://example.com\r\nSec-WebSocket-Version: 13\r\n\r\n"
).encode()
cek(kunci_dari_handshake_klien(permintaan) == KUNCI_CONTOH,
    "handshake klien sah diterima, kunci kembali")
tang = tanggapan_handshake(KUNCI_CONTOH)
cek(tang.startswith(b"HTTP/1.1 101") and TERIMA_CONTOH.encode() in tang,
    "tanggapan 101 membawa accept yang benar")

# Connection/Upgrade sebagai daftar token (bentuk umum di alam liar)
permintaan2 = permintaan.replace(b"Connection: Upgrade",
                                 b"Connection: keep-alive, Upgrade")
cek(kunci_dari_handshake_klien(permintaan2) == KUNCI_CONTOH,
    "token Connection berdaftar diterima")

for rusak, nama in [
        (permintaan.replace(b"GET", b"POST", 1), "metode bukan GET"),
        (permintaan.replace(b"websocket", b"h2c", 1), "Upgrade salah"),
        (permintaan.replace(b"Version: 13", b"Version: 12"), "versi 12"),
        (permintaan.replace(KUNCI_CONTOH.encode(), b"aGVsbG8="),
         "kunci bukan 16 byte"),
        (permintaan.replace(b"Sec-WebSocket-Key", b"X-Tidak-Ada"),
         "kunci hilang")]:
    cek_galat(lambda r=rusak: kunci_dari_handshake_klien(r),
              GalatHandshake, nama)

# Sisi klien: buat + periksa tanggapan
req, kunci = permintaan_handshake("server.example.com", "/chat",
                                  kunci=KUNCI_CONTOH)
cek(kunci_dari_handshake_klien(req) == KUNCI_CONTOH,
    "permintaan buatan sendiri lolos validasi server")
periksa_tanggapan_server(tang, KUNCI_CONTOH)
lulus += 1
cek_galat(lambda: periksa_tanggapan_server(tang, "aGVsbG9hZ2Fpbg=="),
          GalatHandshake, "accept kunci lain ditolak")
cek_galat(lambda: periksa_tanggapan_server(b"HTTP/1.1 200 OK\r\n\r\n",
                                           KUNCI_CONTOH),
          GalatHandshake, "status 200 ditolak")

# --- Frame: SEMUA contoh 5.7, urai + tulis ulang byte-exact -------
f, pos = baca_frame(FRAME_TEKS_PLAIN)
cek(f.fin and f.opcode == OP_TEKS and f.muatan == b"Hello"
    and not f.bertopeng and pos == len(FRAME_TEKS_PLAIN),
    "contoh teks plain terurai")
cek(tulis_frame(OP_TEKS, b"Hello") == FRAME_TEKS_PLAIN,
    "contoh teks plain tertulis byte-exact")

f, _ = baca_frame(FRAME_TEKS_TOPENG)
cek(f.bertopeng and f.muatan == b"Hello", "contoh bertopeng terurai")
cek(tulis_frame(OP_TEKS, b"Hello", kunci_topeng=KUNCI_TOPENG_RFC)
    == FRAME_TEKS_TOPENG, "contoh bertopeng tertulis byte-exact")

f1, p1 = baca_frame(FRAME_FRAG_1)
f2, _ = baca_frame(FRAME_FRAG_2, 0)
cek(not f1.fin and f1.muatan == b"Hel" and f2.opcode == 0
    and f2.fin and f2.muatan == b"lo", "contoh fragmentasi terurai")
cek(tulis_frame(OP_TEKS, b"Hel", fin=False) == FRAME_FRAG_1
    and tulis_frame(0, b"lo") == FRAME_FRAG_2,
    "contoh fragmentasi tertulis byte-exact")

f, _ = baca_frame(FRAME_PING)
cek(f.opcode == OP_PING and f.muatan == b"Hello", "contoh ping terurai")
cek(tulis_frame(OP_PING, b"Hello") == FRAME_PING, "ping tertulis")
f, _ = baca_frame(FRAME_PONG_TOPENG)
cek(f.opcode == OP_PONG and f.muatan == b"Hello", "contoh pong terurai")
cek(tulis_frame(OP_PONG, b"Hello", kunci_topeng=KUNCI_TOPENG_RFC)
    == FRAME_PONG_TOPENG, "pong tertulis byte-exact")

# Contoh panjang 256 dan 64KiB (kepalanya persis RFC, isi pola kita)
isi256 = bytes(range(256))
mentah = bytes.fromhex("827e0100") + isi256
f, pos = baca_frame(mentah)
cek(f.opcode == OP_BINER and f.muatan == isi256 and pos == len(mentah),
    "contoh biner 256 byte terurai")
cek(tulis_frame(OP_BINER, isi256) == mentah, "biner 256 tertulis")
isi64k = bytes(65536)
mentah = bytes.fromhex("827f0000000000010000") + isi64k
f, _ = baca_frame(mentah)
cek(f.muatan == isi64k, "contoh biner 64KiB terurai")
cek(tulis_frame(OP_BINER, isi64k) == mentah, "biner 64KiB tertulis")

# Batas bentuk panjang: 125 tetap 7-bit, 126 naik 16-bit, dst.
for ukuran, len_kepala in [(0, 2), (125, 2), (126, 4), (65535, 4),
                            (65536, 10)]:
    mentah = tulis_frame(OP_BINER, bytes(ukuran))
    cek(len(mentah) == len_kepala + ukuran,
        f"panjang {ukuran}: kepala {len_kepala} byte")
    f, _ = baca_frame(mentah)
    cek(len(f.muatan) == ukuran, f"panjang {ukuran} terbaca")

# Topeng involusi + dua frame berurutan dalam satu buffer
data = bytes(range(256)) * 3
cek(terapkan_topeng(terapkan_topeng(data, KUNCI_TOPENG_RFC),
                    KUNCI_TOPENG_RFC) == data, "topeng involusi")
gabung = FRAME_TEKS_PLAIN + FRAME_PING
_, p = baca_frame(gabung)
f, _ = baca_frame(gabung, p)
cek(f.opcode == OP_PING, "frame kedua terbaca dari posisi lanjut")

# --- Pelanggaran struktural ---------------------------------------
cek_galat(lambda: baca_frame(bytes([0xC1, 0x00])), GalatProtokol,
          "bit RSV1 terpasang ditolak")
cek_galat(lambda: baca_frame(bytes([0x83, 0x00])), GalatProtokol,
          "opcode 0x3 tak dikenal ditolak")
cek_galat(lambda: baca_frame(bytes([0x09, 0x00])), GalatProtokol,
          "ping terfragmentasi ditolak")
cek_galat(lambda: baca_frame(bytes([0x89, 0x7E, 0x00, 0x7E])
                             + bytes(126)), GalatProtokol,
          "ping 126 byte ditolak")
cek_galat(lambda: baca_frame(bytes([0x82, 0x7F, 0x80]) + bytes(7)),
          GalatProtokol, "bit tertinggi panjang 64-bit ditolak")
cek_galat(lambda: baca_frame(bytes([0x81, 0x05, 0x48])), GalatProtokol,
          "muatan terpotong ditolak")
# Panjang bukan-terpendek DITERIMA (keputusan lingkup tercatat)
f, _ = baca_frame(bytes([0x81, 0x7E, 0x00, 0x05]) + b"Hello")
cek(f.muatan == b"Hello", "panjang 16-bit untuk 5 byte diterima")

print(f"irisan 1: {lulus} cek lulus")
