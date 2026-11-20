"""Konstanta bersama: contoh resmi RFC 6455 5.7 dan jangkar
handshake 1.2/1.3, ditranskripsikan dari teks RFC di
../websocket-ref/rfc6455.txt. Plus transport memori berpasangan
untuk uji mesin keadaan tanpa socket."""

# Handshake contoh RFC: kunci -> terima
KUNCI_CONTOH = "dGhlIHNhbXBsZSBub25jZQ=="
TERIMA_CONTOH = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="

# Contoh frame 5.7 (hex persis seperti tercetak di RFC)
FRAME_TEKS_PLAIN = bytes.fromhex("810548656c6c6f")            # "Hello"
FRAME_TEKS_TOPENG = bytes.fromhex("818537fa213d7f9f4d5158")   # "Hello", kunci 37fa213d
FRAME_FRAG_1 = bytes.fromhex("010348656c")                    # "Hel", fin=0
FRAME_FRAG_2 = bytes.fromhex("80026c6f")                      # "lo", lanjutan fin=1
FRAME_PING = bytes.fromhex("890548656c6c6f")                  # ping "Hello"
FRAME_PONG_TOPENG = bytes.fromhex("8a8537fa213d7f9f4d5158")   # pong bertopeng "Hello"
KUNCI_TOPENG_RFC = bytes.fromhex("37fa213d")


class TransportMemori:
    """Ujung transport in-memory. kirim() mengantar ke kotak masuk
    lawan; ambil(n) membaca tepat n byte dari kotak sendiri."""

    def __init__(self):
        self.masuk = bytearray()
        self.lawan = None

    @classmethod
    def sepasang(cls):
        a, b = cls(), cls()
        a.lawan, b.lawan = b, a
        return a, b

    def kirim(self, data):
        self.lawan.masuk += data

    def ambil(self, n):
        if len(self.masuk) < n:
            raise EOFError("transport memori habis")
        hasil = bytes(self.masuk[:n])
        del self.masuk[:n]
        return hasil
