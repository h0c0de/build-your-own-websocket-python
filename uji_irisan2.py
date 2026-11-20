"""Irisan 2 — mesin keadaan Koneksi di transport memori."""
import sys

sys.path.insert(0, ".")
sys.path.insert(0, "..")

from websocketku import (GalatProtokol, Koneksi, baca_frame, tulis_frame,
                         OP_BINER, OP_LANJUT, OP_PING, OP_PONG, OP_TEKS,
                         OP_TUTUP)
from uji_bersama import TransportMemori

KUNCI = b"\x11\x22\x33\x44"
lulus = 0


def cek(kondisi, pesan):
    global lulus
    assert kondisi, pesan
    lulus += 1


def pasangan():
    ta, tb = TransportMemori.sepasang()
    return Koneksi(ta, "server"), Koneksi(tb, "klien"), ta, tb


def cek_langgar(fungsi, kode, pesan):
    global lulus
    try:
        fungsi()
    except GalatProtokol as g:
        assert g.kode_tutup == kode, f"{pesan}: kode {g.kode_tutup} != {kode}"
        lulus += 1
        return
    raise AssertionError(f"tidak naik GalatProtokol: {pesan}")


# --- Alur normal dua arah -----------------------------------------
srv, kli, ta, tb = pasangan()
kli.kirim_teks("halo server")
cek(srv.terima() == ("teks", "halo server"), "klien->server teks")
srv.kirim_teks("halo klien")
cek(kli.terima() == ("teks", "halo klien"), "server->klien teks")
kli.kirim_biner(b"\x00\x01\x02")
cek(srv.terima() == ("biner", b"\x00\x01\x02"), "biner")
# Frame klien di kabel WAJIB bertopeng; frame server tidak
kli.kirim_teks("cek topeng")
f, _ = baca_frame(bytes(ta.masuk))
cek(f.bertopeng, "frame keluar klien bertopeng di kabel")
ta.masuk.clear()
srv.kirim_teks("cek polos")
f, _ = baca_frame(bytes(tb.masuk))
cek(not f.bertopeng, "frame keluar server tidak bertopeng")

# --- Fragmentasi + ping menyela di tengah --------------------------
srv, kli, ta, tb = pasangan()
kli.kirim_teks("HelloWorld", terfragmentasi=[3, 2])
cek(srv.terima() == ("teks", "HelloWorld"), "fragmen terakit utuh")

# Tulis manual: fragmen, ping menyela, lanjutan — server harus
# menjawab pong DULU (di kotak klien) dan tetap merakit pesan.
srv, kli, ta, tb = pasangan()
tb.kirim(tulis_frame(OP_TEKS, b"Hel", fin=False, kunci_topeng=KUNCI))
tb.kirim(tulis_frame(OP_PING, b"detak", kunci_topeng=KUNCI))
tb.kirim(tulis_frame(OP_LANJUT, b"lo", kunci_topeng=KUNCI))
cek(srv.terima() == ("teks", "Hello"), "ping menyela tidak merusak rakitan")
f, _ = baca_frame(bytes(tb.masuk))
cek(f.opcode == OP_PONG and f.muatan == b"detak",
    "pong otomatis membawa muatan ping yang sama")

# Pong masuk dilaporkan sebagai kejadian
srv, kli, ta, tb = pasangan()
ta.kirim(tulis_frame(OP_PONG, b"balas"))
cek(kli.terima() == ("pong", b"balas"), "pong dilaporkan")

# --- Handshake tutup ------------------------------------------------
srv, kli, ta, tb = pasangan()
kli.tutup(1000, "sampai jumpa")
cek(srv.terima() == ("tutup", 1000, "sampai jumpa"),
    "tutup klien terbaca server")
cek(kli.terima() == ("tutup", 1000, "sampai jumpa"),
    "gema tutup terbaca klien")
# Tutup tanpa muatan -> kode semu 1005
srv, kli, ta, tb = pasangan()
tb.kirim(tulis_frame(OP_TUTUP, b"", kunci_topeng=KUNCI))
cek(srv.terima() == ("tutup", 1005, ""), "tutup kosong -> 1005 lokal")

# --- Pelanggaran peran & keadaan ------------------------------------
def mentah_ke_server(mentah):
    srv, kli, ta, tb = pasangan()
    tb.kirim(mentah)
    return srv

cek_langgar(lambda: mentah_ke_server(
    tulis_frame(OP_TEKS, b"x")).terima(), 1002,
    "frame klien TANPA topeng ditolak server")
cek_langgar(lambda: mentah_ke_server(
    tulis_frame(OP_LANJUT, b"x", kunci_topeng=KUNCI)).terima(), 1002,
    "lanjutan tanpa pesan terbuka ditolak")

def frag_lalu_baru():
    srv = mentah_ke_server(
        tulis_frame(OP_TEKS, b"a", fin=False, kunci_topeng=KUNCI)
        + tulis_frame(OP_BINER, b"b", kunci_topeng=KUNCI))
    srv.terima()
cek_langgar(frag_lalu_baru, 1002, "pesan baru di tengah fragmen ditolak")

srv, kli, ta, tb = pasangan()
ta.kirim(tulis_frame(OP_TEKS, b"x", kunci_topeng=KUNCI))
cek_langgar(kli.terima, 1002, "frame bertopeng ditolak klien")

cek_langgar(lambda: mentah_ke_server(
    tulis_frame(OP_TEKS, b"\xff\xfe", kunci_topeng=KUNCI)).terima(), 1007,
    "teks bukan UTF-8 -> 1007")
cek_langgar(lambda: mentah_ke_server(
    tulis_frame(OP_TUTUP, b"\x03", kunci_topeng=KUNCI)).terima(), 1002,
    "muatan tutup 1 byte ditolak")
cek_langgar(lambda: mentah_ke_server(
    tulis_frame(OP_TUTUP, b"\x03\xed", kunci_topeng=KUNCI)).terima(), 1002,
    "kode tutup 1005 di kabel ditolak")
cek_langgar(lambda: mentah_ke_server(
    tulis_frame(OP_TUTUP, b"\x03\xe8\xff", kunci_topeng=KUNCI)).terima(),
    1007, "alasan tutup bukan UTF-8 -> 1007")

# Pelanggaran juga memancarkan frame tutup berkode ke lawan
srv, kli, ta, tb = pasangan()
tb.kirim(tulis_frame(OP_TEKS, b"polos"))
try:
    srv.terima()
except GalatProtokol:
    pass
f, _ = baca_frame(bytes(tb.masuk))
cek(f.opcode == OP_TUTUP and f.muatan[:2] == b"\x03\xea",
    "server mengirim tutup 1002 saat pelanggaran")

print(f"irisan 2: {lulus} cek lulus")
