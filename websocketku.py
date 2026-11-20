"""websocketku — protokol WebSocket (RFC 6455) dari nol.

Handshake pembuka (HTTP Upgrade), format frame biner, masking,
fragmentasi, dan mesin keadaan koneksi (ping/pong/tutup) — klien
dan server — tanpa pustaka WebSocket apa pun. hashlib/base64
dipakai hanya untuk Sec-WebSocket-Accept (SHA-1 + base64, sesuai
RFC 6455 sendiri); tidak ada pustaka protokol yang dilibatkan.

Inti desainnya: frame adalah satuan kabel, pesan adalah satuan
aplikasi. Kontrol (ping/pong/tutup) hidup DI ANTARA fragmen pesan
dan tidak pernah terfragmentasi sendiri — mesin keadaan di kelas
Koneksi yang menegakkan seluruh aturan itu, bukan parser frame.
"""

import base64
import hashlib
import os
import struct

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

OP_LANJUT = 0x0
OP_TEKS = 0x1
OP_BINER = 0x2
OP_TUTUP = 0x8
OP_PING = 0x9
OP_PONG = 0xA
_OPCODE_SAH = {OP_LANJUT, OP_TEKS, OP_BINER, OP_TUTUP, OP_PING, OP_PONG}

# Kode tutup yang boleh MUNCUL di kabel (RFC 6455 7.4.1/7.4.2):
# 1005/1006/1015 adalah nilai semu untuk API lokal, tidak pernah
# dikirim; 1004 & 1014 dicadangkan/belum; < 1000 tidak terdefinisi.
def _kode_tutup_sah(kode):
    return (1000 <= kode <= 1003 or 1007 <= kode <= 1011
            or 3000 <= kode <= 4999)


class GalatProtokol(Exception):
    """Pelanggaran RFC 6455; kode_tutup = kode yang layak dikirim
    ke lawan bicara sebelum sambungan diputus (1002 protokol,
    1007 data tidak konsisten)."""
    def __init__(self, pesan, kode_tutup=1002):
        super().__init__(pesan)
        self.kode_tutup = kode_tutup


class GalatHandshake(Exception):
    pass


# ------------------------------------------------------------------
# Handshake (RFC 6455 4)

def hitung_terima(kunci):
    """Sec-WebSocket-Accept dari Sec-WebSocket-Key klien."""
    sha = hashlib.sha1((kunci + GUID).encode("ascii")).digest()
    return base64.b64encode(sha).decode("ascii")


def _urai_header(mentah):
    """Byte header HTTP -> (baris_pertama, dict header huruf kecil).
    Nilai header digabung koma bila berulang, seperti HTTP."""
    teks = mentah.decode("latin-1")
    baris = teks.split("\r\n")
    header = {}
    for b in baris[1:]:
        if not b:
            continue
        nama, _, nilai = b.partition(":")
        nama = nama.strip().lower()
        nilai = nilai.strip()
        header[nama] = (header[nama] + "," + nilai) if nama in header else nilai
    return baris[0], header


def _token_mengandung(nilai, token):
    return token in (t.strip().lower() for t in nilai.split(","))


def kunci_dari_handshake_klien(mentah):
    """Validasi handshake pembuka dari klien; kembalikan
    Sec-WebSocket-Key-nya, atau naikkan GalatHandshake."""
    baris, h = _urai_header(mentah)
    bagian = baris.split(" ")
    if len(bagian) != 3 or bagian[0] != "GET" or bagian[2] != "HTTP/1.1":
        raise GalatHandshake("baris permintaan harus 'GET <path> HTTP/1.1'")
    if not _token_mengandung(h.get("upgrade", ""), "websocket"):
        raise GalatHandshake("header Upgrade: websocket tidak ada")
    if not _token_mengandung(h.get("connection", ""), "upgrade"):
        raise GalatHandshake("header Connection: Upgrade tidak ada")
    kunci = h.get("sec-websocket-key")
    if not kunci:
        raise GalatHandshake("Sec-WebSocket-Key tidak ada")
    try:
        if len(base64.b64decode(kunci, validate=True)) != 16:
            raise GalatHandshake("Sec-WebSocket-Key harus 16 byte base64")
    except Exception:
        raise GalatHandshake("Sec-WebSocket-Key bukan base64 sah")
    if h.get("sec-websocket-version") != "13":
        raise GalatHandshake("Sec-WebSocket-Version harus 13")
    return kunci


def tanggapan_handshake(kunci):
    return (
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {hitung_terima(kunci)}\r\n"
        "\r\n"
    ).encode("ascii")


def permintaan_handshake(host, path, kunci=None):
    """(byte permintaan, kunci) untuk klien. kunci base64 16 byte;
    dibuat acak bila tidak diberikan."""
    if kunci is None:
        kunci = base64.b64encode(os.urandom(16)).decode("ascii")
    teks = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {kunci}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    )
    return teks.encode("ascii"), kunci


def periksa_tanggapan_server(mentah, kunci):
    """Validasi tanggapan 101 dari server terhadap kunci kita."""
    baris, h = _urai_header(mentah)
    if not baris.startswith("HTTP/1.1 101"):
        raise GalatHandshake(f"status bukan 101: {baris!r}")
    if not _token_mengandung(h.get("upgrade", ""), "websocket"):
        raise GalatHandshake("header Upgrade: websocket tidak ada")
    if not _token_mengandung(h.get("connection", ""), "upgrade"):
        raise GalatHandshake("header Connection: Upgrade tidak ada")
    if h.get("sec-websocket-accept") != hitung_terima(kunci):
        raise GalatHandshake("Sec-WebSocket-Accept tidak cocok")


# ------------------------------------------------------------------
# Frame (RFC 6455 5)

class Frame:
    __slots__ = ("fin", "opcode", "muatan", "bertopeng")

    def __init__(self, fin, opcode, muatan, bertopeng=False):
        self.fin = fin
        self.opcode = opcode
        self.muatan = muatan
        self.bertopeng = bertopeng

    def __eq__(self, lain):
        return (isinstance(lain, Frame) and self.fin == lain.fin
                and self.opcode == lain.opcode
                and self.muatan == lain.muatan)

    def __repr__(self):
        return (f"Frame(fin={self.fin}, opcode={self.opcode:#x}, "
                f"muatan={self.muatan!r})")


def terapkan_topeng(data, kunci):
    """XOR siklik dengan kunci topeng 4 byte (5.3). Simetris:
    menerapkan dua kali mengembalikan data asal."""
    return bytes(b ^ kunci[i % 4] for i, b in enumerate(data))


def tulis_frame(opcode, muatan=b"", fin=True, kunci_topeng=None):
    """Serialkan satu frame. Panjang selalu bentuk TERPENDEK
    (7-bit / 16-bit / 64-bit). kunci_topeng 4 byte -> frame klien;
    None -> frame server."""
    b0 = (0x80 if fin else 0x00) | opcode
    panjang = len(muatan)
    bit_topeng = 0x80 if kunci_topeng is not None else 0x00
    if panjang < 126:
        kepala = struct.pack("!BB", b0, bit_topeng | panjang)
    elif panjang <= 0xFFFF:
        kepala = struct.pack("!BBH", b0, bit_topeng | 126, panjang)
    else:
        kepala = struct.pack("!BBQ", b0, bit_topeng | 127, panjang)
    if kunci_topeng is None:
        return kepala + muatan
    if len(kunci_topeng) != 4:
        raise ValueError("kunci topeng harus 4 byte")
    return kepala + kunci_topeng + terapkan_topeng(muatan, kunci_topeng)


def baca_frame(data, pos=0):
    """Urai satu frame dari data[pos:]; kembalikan (Frame, pos_baru).
    Pelanggaran STRUKTURAL (bit RSV, opcode tak dikenal, kontrol
    terfragmentasi/terlalu panjang, bit tertinggi panjang 64-bit)
    -> GalatProtokol. Panjang bukan-terpendek DITERIMA (RFC mewajibkan
    pengirim, bukan penolakan penerima) — dicatat di CATATAN."""
    if len(data) - pos < 2:
        raise GalatProtokol("data habis sebelum kepala frame")
    b0, b1 = data[pos], data[pos + 1]
    pos += 2
    fin = bool(b0 & 0x80)
    if b0 & 0x70:
        raise GalatProtokol("bit RSV bukan nol tanpa ekstensi")
    opcode = b0 & 0x0F
    if opcode not in _OPCODE_SAH:
        raise GalatProtokol(f"opcode tidak dikenal: {opcode:#x}")
    bertopeng = bool(b1 & 0x80)
    panjang = b1 & 0x7F
    if panjang == 126:
        if len(data) - pos < 2:
            raise GalatProtokol("data habis di panjang 16-bit")
        panjang = struct.unpack_from("!H", data, pos)[0]
        pos += 2
    elif panjang == 127:
        if len(data) - pos < 8:
            raise GalatProtokol("data habis di panjang 64-bit")
        if data[pos] & 0x80:
            raise GalatProtokol("bit tertinggi panjang 64-bit harus 0")
        panjang = struct.unpack_from("!Q", data, pos)[0]
        pos += 8
    if opcode >= 0x8:
        if not fin:
            raise GalatProtokol("frame kontrol tidak boleh terfragmentasi")
        if panjang > 125:
            raise GalatProtokol("frame kontrol maksimal 125 byte")
    kunci = None
    if bertopeng:
        if len(data) - pos < 4:
            raise GalatProtokol("data habis di kunci topeng")
        kunci = data[pos:pos + 4]
        pos += 4
    if len(data) - pos < panjang:
        raise GalatProtokol("data habis di tengah muatan")
    muatan = data[pos:pos + panjang]
    pos += panjang
    if kunci is not None:
        muatan = terapkan_topeng(muatan, kunci)
    return Frame(fin, opcode, muatan, bertopeng), pos


# ------------------------------------------------------------------
# Koneksi: mesin keadaan pesan di atas transport byte

class Koneksi:
    """Satu ujung WebSocket di atas transport berpasangan.

    transport harus punya: kirim(bytes) dan ambil(n) -> bytes
    (tepat n byte; naikkan EOFError bila sambungan putus).

    peran: 'server' (menuntut frame lawan bertopeng) atau
    'klien' (menuntut frame lawan TIDAK bertopeng, dan menutupi
    frame sendiri dengan kunci acak baru tiap frame)."""

    def __init__(self, transport, peran):
        if peran not in ("server", "klien"):
            raise ValueError("peran harus 'server' atau 'klien'")
        self.t = transport
        self.peran = peran
        self._frag_opcode = None      # opcode pesan yang sedang terfragmentasi
        self._frag_bagian = []
        self._tutup_terkirim = False
        self._tutup_terterima = False
        self.kode_tutup_masuk = None

    # -- kirim -----------------------------------------------------

    def _kirim_frame(self, opcode, muatan=b"", fin=True):
        kunci = os.urandom(4) if self.peran == "klien" else None
        self.t.kirim(tulis_frame(opcode, muatan, fin=fin, kunci_topeng=kunci))

    def kirim_teks(self, teks, terfragmentasi=None):
        """Kirim pesan teks. terfragmentasi = daftar ukuran potong
        (untuk uji); None = satu frame."""
        self._kirim_pesan(OP_TEKS, teks.encode("utf-8"), terfragmentasi)

    def kirim_biner(self, data, terfragmentasi=None):
        self._kirim_pesan(OP_BINER, bytes(data), terfragmentasi)

    def _kirim_pesan(self, opcode, data, terfragmentasi):
        if self._tutup_terkirim:
            raise GalatProtokol("koneksi sudah ditutup dari sisi ini")
        if not terfragmentasi:
            self._kirim_frame(opcode, data, fin=True)
            return
        potong = []
        sisa = data
        for ukuran in terfragmentasi:
            potong.append(sisa[:ukuran])
            sisa = sisa[ukuran:]
        potong.append(sisa)
        for i, bagian in enumerate(potong):
            op = opcode if i == 0 else OP_LANJUT
            self._kirim_frame(op, bagian, fin=(i == len(potong) - 1))

    def ping(self, muatan=b""):
        if len(muatan) > 125:
            raise GalatProtokol("ping maksimal 125 byte")
        self._kirim_frame(OP_PING, muatan)

    def tutup(self, kode=1000, alasan=""):
        muatan = struct.pack("!H", kode) + alasan.encode("utf-8")
        if len(muatan) > 125:
            raise GalatProtokol("muatan tutup maksimal 125 byte")
        if not self._tutup_terkirim:
            self._kirim_frame(OP_TUTUP, muatan)
            self._tutup_terkirim = True

    # -- terima ----------------------------------------------------

    def _ambil_tepat(self, n):
        return self.t.ambil(n)

    def _baca_satu_frame(self):
        # Kepala dibaca bertahap dari transport (bukan buffer utuh):
        # 2 byte dasar, lalu panjang tambahan, kunci, muatan.
        dua = self._ambil_tepat(2)
        b0, b1 = dua[0], dua[1]
        ekstra = b""
        panjang = b1 & 0x7F
        if panjang == 126:
            ekstra = self._ambil_tepat(2)
        elif panjang == 127:
            ekstra = self._ambil_tepat(8)
        kunci = self._ambil_tepat(4) if (b1 & 0x80) else b""
        panjang_asli = panjang
        if panjang == 126:
            panjang_asli = struct.unpack("!H", ekstra)[0]
        elif panjang == 127:
            panjang_asli = struct.unpack("!Q", ekstra)[0]
        muatan = self._ambil_tepat(panjang_asli) if panjang_asli else b""
        mentah = dua + ekstra + kunci + muatan
        frame, _ = baca_frame(mentah)
        return frame

    def terima(self):
        """Baca sampai satu KEJADIAN utuh; kembalikan salah satu:
        ('teks', str) | ('biner', bytes) | ('pong', bytes) |
        ('tutup', kode, alasan). Ping dijawab pong otomatis dan
        tidak dilaporkan. Pelanggaran -> GalatProtokol (dan frame
        tutup berkode sesuai dikirim lebih dulu)."""
        while True:
            try:
                frame = self._baca_satu_frame()
            except GalatProtokol:
                raise
            except EOFError:
                raise GalatProtokol("sambungan putus tanpa frame tutup",
                                     kode_tutup=1006)
            try:
                kejadian = self._proses(frame)
            except GalatProtokol as g:
                if not self._tutup_terkirim:
                    try:
                        self.tutup(g.kode_tutup if g.kode_tutup != 1006
                                   else 1002)
                    except Exception:
                        pass
                raise
            if kejadian is not None:
                return kejadian

    def _proses(self, frame):
        # Aturan peran masking (5.1): server menuntut klien bertopeng,
        # klien menuntut server TIDAK bertopeng.
        if self.peran == "server" and not frame.bertopeng:
            raise GalatProtokol("frame klien ke server wajib bertopeng")
        if self.peran == "klien" and frame.bertopeng:
            raise GalatProtokol("frame server ke klien dilarang bertopeng")
        if self._tutup_terterima:
            raise GalatProtokol("frame datang sesudah tutup")

        if frame.opcode == OP_PING:
            self._kirim_frame(OP_PONG, frame.muatan)
            return None
        if frame.opcode == OP_PONG:
            return ("pong", frame.muatan)
        if frame.opcode == OP_TUTUP:
            return self._proses_tutup(frame)

        if frame.opcode == OP_LANJUT:
            if self._frag_opcode is None:
                raise GalatProtokol("frame lanjutan tanpa pesan terbuka")
            self._frag_bagian.append(frame.muatan)
            if not frame.fin:
                return None
            opcode, self._frag_opcode = self._frag_opcode, None
            data = b"".join(self._frag_bagian)
            self._frag_bagian = []
            return self._kejadian_pesan(opcode, data)

        # Frame data baru (teks/biner)
        if self._frag_opcode is not None:
            raise GalatProtokol("pesan baru mulai sebelum fragmen selesai")
        if not frame.fin:
            self._frag_opcode = frame.opcode
            self._frag_bagian = [frame.muatan]
            return None
        return self._kejadian_pesan(frame.opcode, frame.muatan)

    def _kejadian_pesan(self, opcode, data):
        if opcode == OP_TEKS:
            try:
                return ("teks", data.decode("utf-8"))
            except UnicodeDecodeError:
                raise GalatProtokol("pesan teks bukan UTF-8 sah",
                                    kode_tutup=1007)
        return ("biner", data)

    def _proses_tutup(self, frame):
        muatan = frame.muatan
        if len(muatan) == 1:
            raise GalatProtokol("muatan tutup 1 byte tidak sah")
        kode, alasan = 1005, ""
        if len(muatan) >= 2:
            kode = struct.unpack("!H", muatan[:2])[0]
            if not _kode_tutup_sah(kode):
                raise GalatProtokol(f"kode tutup tidak boleh di kabel: {kode}")
            try:
                alasan = muatan[2:].decode("utf-8")
            except UnicodeDecodeError:
                raise GalatProtokol("alasan tutup bukan UTF-8 sah",
                                    kode_tutup=1007)
        self._tutup_terterima = True
        self.kode_tutup_masuk = kode
        if not self._tutup_terkirim:
            # Gema tutup: balas dengan muatan yang sama (7.1.2).
            self._kirim_frame(OP_TUTUP, muatan)
            self._tutup_terkirim = True
        return ("tutup", kode, alasan)


# ------------------------------------------------------------------
# Transport socket + jembatan handshake ujung-ke-ujung

class TransportSocket:
    def __init__(self, sock):
        self.sock = sock
        self._sisa = b""

    def kirim(self, data):
        self.sock.sendall(data)

    def ambil(self, n):
        while len(self._sisa) < n:
            potong = self.sock.recv(65536)
            if not potong:
                raise EOFError("socket ditutup lawan")
            self._sisa += potong
        hasil, self._sisa = self._sisa[:n], self._sisa[n:]
        return hasil

    def ambil_sampai_header_habis(self):
        """Baca sampai CRLFCRLF; kembalikan byte header SAJA dan
        simpan kelebihan (awal frame) di buffer internal."""
        while b"\r\n\r\n" not in self._sisa:
            potong = self.sock.recv(65536)
            if not potong:
                raise EOFError("socket ditutup saat handshake")
            self._sisa += potong
        kepala, _, sisa = self._sisa.partition(b"\r\n\r\n")
        self._sisa = sisa
        return kepala + b"\r\n\r\n"


def terima_koneksi(sock):
    """Sisi server: jalankan handshake di socket yang sudah
    terhubung, kembalikan Koneksi berperan server."""
    t = TransportSocket(sock)
    mentah = t.ambil_sampai_header_habis()
    kunci = kunci_dari_handshake_klien(mentah)
    t.kirim(tanggapan_handshake(kunci))
    return Koneksi(t, "server")


def sambung_ke(sock, host, path="/"):
    """Sisi klien: handshake di socket yang sudah terhubung ke
    server, kembalikan Koneksi berperan klien."""
    t = TransportSocket(sock)
    permintaan, kunci = permintaan_handshake(host, path)
    t.kirim(permintaan)
    mentah = t.ambil_sampai_header_habis()
    periksa_tanggapan_server(mentah, kunci)
    return Koneksi(t, "klien")
