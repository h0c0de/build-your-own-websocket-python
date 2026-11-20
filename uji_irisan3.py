"""Irisan 3 — interop HIDUP melawan pustaka websockets 17.4.

Dua arah: server-ku x klien mereka, dan server mereka x klien-ku,
di socket TCP sungguhan (127.0.0.1). Jalankan dengan Python venv
wasit: ../websocket-ref/venv/bin/python uji_irisan3.py
"""
import socket
import sys
import threading

sys.path.insert(0, ".")
sys.path.insert(0, "..")

from websocketku import Koneksi, sambung_ke, terima_koneksi
from websockets.sync.client import connect as konek_mereka
from websockets.sync.server import serve as layani_mereka

lulus = 0


def cek(kondisi, pesan):
    global lulus
    assert kondisi, pesan
    lulus += 1


BESAR = bytes(range(256)) * 400          # 102.400 byte


def jalankan_serverku():
    """Server echo-ku di thread; kembalikan (port, thread, soket)."""
    induk = socket.socket()
    induk.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    induk.bind(("127.0.0.1", 0))
    induk.listen(1)
    port = induk.getsockname()[1]

    def tugas():
        mentah, _ = induk.accept()
        mentah.settimeout(15)
        kon = terima_koneksi(mentah)
        while True:
            jenis, *isi = kon.terima()
            if jenis == "teks":
                kon.kirim_teks(isi[0])
            elif jenis == "biner":
                kon.kirim_biner(isi[0])
            elif jenis == "tutup":
                break
        mentah.close()
        induk.close()

    th = threading.Thread(target=tugas, daemon=True)
    th.start()
    return port, th


def jalankan_server_mereka():
    def penangan(ws):
        for pesan in ws:
            ws.send(pesan)

    server = layani_mereka(penangan, "127.0.0.1", 0)
    port = server.socket.getsockname()[1]
    th = threading.Thread(target=server.serve_forever, daemon=True)
    th.start()
    return port, server


# --- A: server-KU x klien MEREKA -----------------------------------
port, th = jalankan_serverku()
with konek_mereka(f"ws://127.0.0.1:{port}/") as ws:
    ws.send("halo dari klien mereka")
    cek(ws.recv() == "halo dari klien mereka", "A: echo teks")
    ws.send(BESAR)
    cek(ws.recv() == BESAR, "A: echo biner 100 KB")
    penunggu = ws.ping(b"detakku")
    cek(penunggu.wait(5), "A: ping-ku dijawab pong server-ku")
    ws.close(code=3000, reason="uji selesai")
th.join(5)
cek(not th.is_alive(), "A: server-ku menutup bersih sesudah close 3000")

# --- B: server MEREKA x klien-KU ------------------------------------
port, server_mereka = jalankan_server_mereka()
mentah = socket.create_connection(("127.0.0.1", port), timeout=15)
kon = sambung_ke(mentah, f"127.0.0.1:{port}", "/")
kon.kirim_teks("halo dari klienku")
cek(kon.terima() == ("teks", "halo dari klienku"), "B: echo teks")
kon.kirim_biner(BESAR)
cek(kon.terima() == ("biner", BESAR), "B: echo biner 100 KB")
kon.kirim_teks("pesan terfragmentasi", terfragmentasi=[5, 5])
cek(kon.terima() == ("teks", "pesan terfragmentasi"),
    "B: fragmenku terakit di server mereka")
kon.ping(b"detak")
cek(kon.terima() == ("pong", b"detak"), "B: pong mereka untuk ping-ku")
kon.tutup(1000, "selesai")
jenis, kode, alasan = kon.terima()
cek(jenis == "tutup" and kode == 1000, "B: gema tutup 1000 dari mereka")
mentah.close()
server_mereka.shutdown()

# --- C: server-KU x klien-KU (asap di socket asli) ------------------
port, th = jalankan_serverku()
mentah = socket.create_connection(("127.0.0.1", port), timeout=15)
kon = sambung_ke(mentah, f"127.0.0.1:{port}", "/")
kon.kirim_teks("lingkar penuh", terfragmentasi=[3, 3])
cek(kon.terima() == ("teks", "lingkar penuh"), "C: echo terfragmentasi")
kon.tutup()
jenis, kode, _ = kon.terima()
cek(jenis == "tutup" and kode == 1000, "C: tutup bersih")
mentah.close()
th.join(5)

print(f"irisan 3: {lulus} cek lulus")
