# -*- coding: utf-8 -*-
from __future__ import annotations

import hashlib
import hmac
import errno
import os
import queue
import secrets
import socket
import struct
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
from typing import Any, Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend

CHANNELS = ("IF100", "MATH101", "SPS101")
SHA3_512_DIGEST = 64
MAX_FRAME = 16 * 1024 * 1024

MSG_ENROLL_OK = "SUCCESS"
MSG_AUTH_OK = "Authentication Successful"
MSG_AUTH_FAIL = "Authentication Unsuccessful"
MSG_CHANNEL_UNAVAILABLE = "Channel Unavailable"


def english_socket_connect_error(exc: OSError) -> str:
    winerr = getattr(exc, "winerror", None)
    if winerr == 10061 or exc.errno in (errno.ECONNREFUSED,):
        return (
            "Connection refused: nothing is accepting TCP connections on that IP/port "
            "(is the server running and listening?)."
        )
    if winerr == 10060 or exc.errno in (errno.ETIMEDOUT,):
        return "Connection timed out: check IP/port, firewall, and network path."
    if winerr == 10051 or exc.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH):
        return "Network unreachable: check IP address and routing/firewall."
    return f"Socket error (errno={exc.errno}, winerror={winerr}): {exc.__class__.__name__}"


def sha3_512(data: bytes) -> bytes:
    return hashlib.sha3_512(data).digest()


def hmac_sha3_512(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha3_512).digest()


def derive_password_side_keys_from_rev_hash(rev_hash: bytes) -> Tuple[bytes, bytes]:
    aes_key = rev_hash[:32]
    iv = rev_hash[32:48]
    return aes_key, iv


def aes_cbc_pkcs7_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    padder = sym_padding.PKCS7(128).padder()
    data = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    return enc.update(data) + enc.finalize()


def aes_cbc_pkcs7_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf.extend(chunk)
    return bytes(buf)


def recv_frame(sock: socket.socket) -> bytes:
    hdr = recv_exact(sock, 4)
    ln = struct.unpack("!I", hdr)[0]
    if ln > MAX_FRAME:
        raise ValueError("frame too large")
    return recv_exact(sock, ln)


def send_frame(sock: socket.socket, payload: bytes) -> None:
    sock.sendall(struct.pack("!I", len(payload)) + payload)


def rsa_encrypt_pkcs1v15(pub: rsa.RSAPublicKey, plaintext: bytes) -> bytes:
    # cryptography does not support OAEP+SHA3-512; project only requires RSA encryption here.
    return pub.encrypt(plaintext, padding.PKCS1v15())


def rsa_verify_sha3_512(pub: rsa.RSAPublicKey, data: bytes, sig: bytes) -> None:
    pub.verify(sig, data, padding.PKCS1v15(), hashes.SHA3_512())


def pack_enrollment_plaintext(username: str, channel: str, pwd_hash: bytes, rev_hash: bytes) -> bytes:
    u = username.encode("utf-8")
    c = channel.encode("utf-8")
    if len(pwd_hash) != 64 or len(rev_hash) != 64:
        raise ValueError("invalid hash length")
    if len(u) > 200 or len(c) > 32:
        raise ValueError("field too long")
    return struct.pack("!H", len(u)) + u + struct.pack("!H", len(c)) + c + pwd_hash + rev_hash


def rsa_sig_len_bits(pub: rsa.RSAPublicKey) -> int:
    return pub.public_numbers().n.bit_length()


def rsa_sig_bytes(pub: rsa.RSAPublicKey) -> int:
    bits = rsa_sig_len_bits(pub)
    return (bits + 7) // 8


class SecureClientApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        root.title("CS432/532 Secure Channel Client")
        self.log_q: "queue.Queue[str]" = queue.Queue()
        self.sock: Optional[socket.socket] = None
        self.recv_thread: Optional[threading.Thread] = None
        self.io_lock = threading.Lock()
        self.authenticated = False
        self.channel_aes: Optional[bytes] = None
        self.channel_iv: Optional[bytes] = None
        self.channel_hmac: Optional[bytes] = None
        self.subscribed_channel: Optional[str] = None

        _base = os.path.dirname(os.path.abspath(__file__))
        self.path_enc_pub = tk.StringVar(value=os.path.join(_base, "server_enc_dec_pub.pem"))
        self.path_sign_pub = tk.StringVar(value=os.path.join(_base, "server_sign_verify_pub.pem"))
        self.host_var = tk.StringVar(value="127.0.0.1")
        self.port_var = tk.StringVar(value="53000")
        self.user_var = tk.StringVar()
        self.pass_var = tk.StringVar()
        self.channel_var = tk.StringVar(value=CHANNELS[0])

        self.pub_enc: Optional[rsa.RSAPublicKey] = None
        self.pub_sign: Optional[rsa.RSAPublicKey] = None

        r = 0
        self.gui_log = scrolledtext.ScrolledText(root, height=12, width=100, state="disabled")
        self.gui_log.grid(row=r, column=0, columnspan=3, sticky="nsew", padx=6, pady=4)
        r += 1

        fk = ttk.LabelFrame(root, text="Server RSA public PEM (file system)")
        fk.grid(row=r, column=0, columnspan=3, sticky="ew", padx=6, pady=4)
        ttk.Label(fk, text="Encryption public key:").grid(row=0, column=0, sticky="w")
        ttk.Entry(fk, textvariable=self.path_enc_pub, width=60).grid(row=0, column=1, padx=4)
        ttk.Button(fk, text="Browse", command=self.browse_enc_pub).grid(row=0, column=2)
        ttk.Label(fk, text="Signature verification public key:").grid(row=1, column=0, sticky="w")
        ttk.Entry(fk, textvariable=self.path_sign_pub, width=60).grid(row=1, column=1, padx=4)
        ttk.Button(fk, text="Browse", command=self.browse_sign_pub).grid(row=1, column=2)
        r += 1

        fc = ttk.LabelFrame(root, text="Server address")
        fc.grid(row=r, column=0, columnspan=3, sticky="ew", padx=6, pady=4)
        ttk.Label(fc, text="IP:").grid(row=0, column=0)
        ttk.Entry(fc, textvariable=self.host_var, width=18).grid(row=0, column=1, sticky="w")
        ttk.Label(fc, text="Port:").grid(row=0, column=2)
        ttk.Entry(fc, textvariable=self.port_var, width=8).grid(row=0, column=3)
        r += 1

        fe = ttk.LabelFrame(root, text="Enrollment — password is not stored on client")
        fe.grid(row=r, column=0, columnspan=3, sticky="ew", padx=6, pady=4)
        ttk.Label(fe, text="Username:").grid(row=0, column=0)
        ttk.Entry(fe, textvariable=self.user_var, width=24).grid(row=0, column=1, sticky="w")
        ttk.Label(fe, text="Password:").grid(row=0, column=2)
        ttk.Entry(fe, textvariable=self.pass_var, width=20, show="*").grid(row=0, column=3)
        ttk.Label(fe, text="Channel:").grid(row=1, column=0)
        ttk.Combobox(fe, textvariable=self.channel_var, values=CHANNELS, state="readonly", width=12).grid(
            row=1, column=1, sticky="w"
        )
        ttk.Button(fe, text="Enroll", command=self.do_enroll).grid(row=1, column=2, padx=6)
        r += 1

        fl = ttk.LabelFrame(root, text="Login (Authentication) — enter password every time")
        fl.grid(row=r, column=0, columnspan=3, sticky="ew", padx=6, pady=4)
        self.login_pass_var = tk.StringVar()
        ttk.Label(fl, text="Login password:").grid(row=0, column=0)
        ttk.Entry(fl, textvariable=self.login_pass_var, width=24, show="*").grid(row=0, column=1, sticky="w")
        ttk.Button(fl, text="Connect and Login", command=self.do_login).grid(row=0, column=2, padx=6)
        r += 1

        fm = ttk.LabelFrame(root, text="Secure broadcast (after login only)")
        fm.grid(row=r, column=0, columnspan=3, sticky="ew", padx=6, pady=4)
        self.msg_var = tk.StringVar()
        ttk.Entry(fm, textvariable=self.msg_var, width=70).grid(row=0, column=0, padx=4)
        self.btn_send = ttk.Button(fm, text="Send", command=self.send_broadcast, state="disabled")
        self.btn_send.grid(row=0, column=1)
        ttk.Button(fm, text="Disconnect", command=self.disconnect).grid(row=0, column=2, padx=6)
        r += 1

        frx = ttk.LabelFrame(root, text="Decrypted incoming broadcast messages")
        frx.grid(row=r, column=0, columnspan=3, sticky="nsew", padx=6, pady=4)
        self.incoming_text = scrolledtext.ScrolledText(frx, height=8, width=100, state="disabled")
        self.incoming_text.pack(fill="both", expand=True)
        r += 1

        root.rowconfigure(r - 1, weight=1)
        root.columnconfigure(0, weight=1)

        self.root.after(100, self._drain_log_queue)

    def _ui_info(self, title: str, msg: str) -> None:
        def _show() -> None:
            messagebox.showinfo(title, msg, parent=self.root)

        self.root.after(0, _show)

    def _ui_warn(self, title: str, msg: str) -> None:
        def _show() -> None:
            messagebox.showwarning(title, msg, parent=self.root)

        self.root.after(0, _show)

    def _ui_error(self, title: str, msg: str) -> None:
        def _show() -> None:
            messagebox.showerror(title, msg, parent=self.root)

        self.root.after(0, _show)

    def browse_enc_pub(self) -> None:
        p = filedialog.askopenfilename(title="server_enc_dec_pub.pem", filetypes=[("PEM", "*.pem"), ("All", "*.*")])
        if p:
            self.path_enc_pub.set(p)

    def browse_sign_pub(self) -> None:
        p = filedialog.askopenfilename(title="server_sign_verify_pub.pem", filetypes=[("PEM", "*.pem"), ("All", "*.*")])
        if p:
            self.path_sign_pub.set(p)

    def log_line(self, s: str) -> None:
        self.log_q.put(s)

    def _drain_log_queue(self) -> None:
        try:
            while True:
                s = self.log_q.get_nowait()
                self.gui_log.configure(state="normal")
                self.gui_log.insert("end", s + "\n")
                self.gui_log.see("end")
                self.gui_log.configure(state="disabled")
        except queue.Empty:
            pass
        self.root.after(100, self._drain_log_queue)

    def _load_pub_keys(self) -> bool:
        pe = self.path_enc_pub.get().strip()
        ps = self.path_sign_pub.get().strip()
        if not pe or not ps:
            self._ui_error("Error", "Please select both server public PEM file paths.")
            return False
        try:
            with open(pe, "rb") as f:
                self.pub_enc = serialization.load_pem_public_key(f.read())
            with open(ps, "rb") as f:
                self.pub_sign = serialization.load_pem_public_key(f.read())
        except Exception as e:
            self._ui_error("PEM", str(e))
            return False
        assert isinstance(self.pub_enc, rsa.RSAPublicKey)
        assert isinstance(self.pub_sign, rsa.RSAPublicKey)
        self.log_line("Server public keys loaded.")
        ne = self.pub_enc.public_numbers().n
        ns = self.pub_sign.public_numbers().n
        self.log_line("Enc modulus (hex, prefix): " + hex(ne)[:66] + "...")
        self.log_line("Sign modulus (hex, prefix): " + hex(ns)[:66] + "...")
        return True

    def _tcp_connect(self) -> Optional[socket.socket]:
        if not self._load_pub_keys():
            return None
        host = self.host_var.get().strip()
        try:
            port = int(self.port_var.get().strip())
        except ValueError:
            self._ui_error("Error", "Please enter a valid port.")
            return None
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(10.0)
            s.connect((host, port))
            s.settimeout(None)
        except OSError as e:
            self._ui_error(
                "Connection",
                f"{english_socket_connect_error(e)}\nCheck the IP/port and try again.",
            )
            try:
                s.close()
            except OSError:
                pass
            return None
        return s

    def disconnect(self) -> None:
        self.authenticated = False
        self.channel_aes = self.channel_iv = self.channel_hmac = None
        if self.sock:
            try:
                send_frame(self.sock, b"X")
            except OSError:
                pass
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None
        self._set_send_enabled(False)
        self.log_line("Disconnected.")

    def _set_send_enabled(self, on: bool) -> None:
        self.btn_send.configure(state=("normal" if on else "disabled"))

    def do_enroll(self) -> None:
        threading.Thread(target=self._enroll_worker, daemon=True).start()

    def _enroll_worker(self) -> None:
        with self.io_lock:
            self._enroll_worker_locked()

    def _enroll_worker_locked(self) -> None:
        sock = self._tcp_connect()
        if not sock:
            return
        try:
            username = self.user_var.get().strip()
            password = self.pass_var.get()
            channel = self.channel_var.get().strip()
            if not username or not password:
                self._ui_error("Enrollment", "Username and password are required.")
                return
            if channel not in CHANNELS:
                self._ui_error("Enrollment", "Invalid channel selection.")
                return
            pwd_h = sha3_512(password.encode("utf-8"))
            rev_h = sha3_512(password[::-1].encode("utf-8"))
            self.log_line(f"SHA3-512(password) (hex): {pwd_h.hex()}")
            self.log_line(f"SHA3-512(reversed password) (hex): {rev_h.hex()}")
            plain = pack_enrollment_plaintext(username, channel, pwd_h, rev_h)
            assert self.pub_enc is not None
            rsa_cipher = rsa_encrypt_pkcs1v15(self.pub_enc, plain)
            self.log_line(f"Enrollment RSA ciphertext length: {len(rsa_cipher)} bytes (PKCS#1 v1.5)")
            send_frame(sock, b"E" + rsa_cipher)
            resp = recv_frame(sock)
            if resp[:1] != b"R":
                self.log_line("Unexpected enrollment response")
                return
            ln = struct.unpack_from("!H", resp, 1)[0]
            body = resp[3 : 3 + ln]
            sig = resp[3 + ln :]
            assert self.pub_sign is not None
            rsa_verify_sha3_512(self.pub_sign, body, sig)
            self.log_line("Enrollment response signature verification: SUCCESS")
            self.log_line(f"Signature (hex, first 64): {sig.hex()[:64]}...")
            txt = body.decode("utf-8", errors="replace")
            self.log_line(f"Server message: {txt}")
            if txt == MSG_ENROLL_OK:
                self._ui_info("Enrollment", "Enrollment successful.")
            else:
                self._ui_warn("Enrollment", f"Enrollment failed or error: {txt}")
        except Exception as e:
            self.log_line(f"Enrollment error: {e}")
            self._ui_error("Enrollment", str(e))
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def do_login(self) -> None:
        threading.Thread(target=self._login_worker, daemon=True).start()

    def _login_worker(self) -> None:
        with self.io_lock:
            self._login_worker_locked()

    def _login_worker_locked(self) -> None:
        if self.sock:
            self._ui_info("Info", "Please disconnect first.")
            return
        sock = self._tcp_connect()
        if not sock:
            return
        self.sock = sock
        try:
            username = self.user_var.get().strip()
            pw = self.login_pass_var.get()
            if not username or not pw:
                self._ui_error("Login", "Please enter username and password.")
                self.disconnect()
                return
            send_frame(sock, b"A" + b"1" + username.encode("utf-8"))
            self.log_line(f"Auth request (cleartext username): {username}")
            chfr = recv_frame(sock)
            if chfr[:1] != b"C" or len(chfr) != 1 + 16:
                self.log_line("Challenge format error")
                self._ui_error("Login", "Invalid challenge from server.")
                self.disconnect()
                return
            challenge = chfr[1:]
            self.log_line(f"Challenge (hex): {challenge.hex()}")
            pwd_digest = sha3_512(pw.encode("utf-8"))
            hkey = pwd_digest[:32]
            mac = hmac_sha3_512(hkey, challenge)
            self.log_line(f"HMAC key (lower 32 bytes of SHA3-512(password), hex): {hkey.hex()}")
            self.log_line(f"HMAC-SHA3-512(challenge) (hex): {mac.hex()}")
            send_frame(sock, b"A" + b"2" + mac)
            pack = recv_frame(sock)
            if pack[:1] != b"K":
                self.log_line("Auth result format error")
                self._ui_error("Login", "Invalid auth response from server.")
                self.disconnect()
                return
            rest = pack[1:]
            assert self.pub_sign is not None
            sig_len = rsa_sig_bytes(self.pub_sign)
            if len(rest) <= sig_len:
                self.log_line("Auth packet too short")
                self._ui_error("Login", "Auth packet too short (missing signature?).")
                self.disconnect()
                return
            outer_cipher = rest[:-sig_len]
            sig = rest[-sig_len:]
            rsa_verify_sha3_512(self.pub_sign, outer_cipher, sig)
            self.log_line("Auth response RSA signature verification: SUCCESS")
            self.log_line(f"Outer ciphertext (hex, first 48): {outer_cipher.hex()[:48]}...")
            rev_digest = sha3_512(pw[::-1].encode("utf-8"))
            aes_k, iv = derive_password_side_keys_from_rev_hash(rev_digest)
            self.log_line(f"AES key derived from SHA3-512(reversed password) (hex): {aes_k.hex()}")
            self.log_line(f"AES IV hex: {iv.hex()}")
            try:
                outer_plain = aes_cbc_pkcs7_decrypt(aes_k, iv, outer_cipher)
            except Exception as e:
                self.log_line(f"Decryption error (wrong password / unknown username / corrupted packet): {e}")
                self._ui_error(
                    "Login",
                    "Wrong password, unknown username, or corrupted packet; cannot decrypt.",
                )
                self.disconnect()
                return
            if outer_plain.startswith(MSG_CHANNEL_UNAVAILABLE.encode("utf-8")):
                self._ui_warn("Channel", "Channel unavailable; generate keys on the server.")
                self.disconnect()
                return
            if outer_plain.startswith(MSG_AUTH_FAIL.encode("utf-8")):
                self._ui_warn(
                    "Login",
                    f"{MSG_AUTH_FAIL}\n(This can also happen if the username is already connected elsewhere.)",
                )
                self.disconnect()
                return
            okb = MSG_AUTH_OK.encode("utf-8")
            if not outer_plain.startswith(okb):
                self.log_line("Unexpected auth plaintext")
                self._ui_error("Login", "Unexpected auth response after decryption.")
                self.disconnect()
                return
            if len(outer_plain) < len(okb) + 1 or outer_plain[len(okb) : len(okb) + 1] != b"\n":
                self._ui_error("Login", "Malformed successful auth plaintext.")
                self.disconnect()
                return
            inner_blob = outer_plain[len(okb) + 1 :]
            if len(inner_blob) < 4:
                self._ui_error("Login", "Malformed inner key blob.")
                self.disconnect()
                return
            ilen = struct.unpack_from("!I", inner_blob, 0)[0]
            inner_cipher = inner_blob[4 : 4 + ilen]
            inner_plain = aes_cbc_pkcs7_decrypt(aes_k, iv, inner_cipher)
            if len(inner_plain) < 80 + 2:
                self._ui_error("Login", "Failed to parse channel key material.")
                self.disconnect()
                return
            ca = inner_plain[:32]
            ci = inner_plain[32:48]
            hk = inner_plain[48:80]
            lc = struct.unpack_from("!H", inner_plain, 80)[0]
            chname = inner_plain[82 : 82 + lc].decode("utf-8")
            self.channel_aes, self.channel_iv, self.channel_hmac = ca, ci, hk
            self.subscribed_channel = chname
            self.log_line(f"Channel assigned by server: {chname}")
            self.authenticated = True
            self.log_line(f"Channel AES key (hex): {ca.hex()}")
            self.log_line(f"Channel IV (hex): {ci.hex()}")
            self.log_line(f"Channel HMAC key (hex): {hk.hex()}")
            self._ui_info("Login", "Authentication successful.")
            self.root.after(0, self._set_send_enabled, True)
            self.recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
            self.recv_thread.start()
        except Exception as e:
            self.log_line(f"Login error: {e}")
            self._ui_error("Login", str(e))
            self.disconnect()

    def _recv_loop(self) -> None:
        assert self.sock is not None
        try:
            while True:
                fr = recv_frame(self.sock)
                op = fr[:1]
                body = fr[1:]
                if op == b"B":
                    self._handle_broadcast(body)
                elif op == b"X":
                    break
                else:
                    self.log_line(f"Unknown server message op: {op!r}")
        except (ConnectionError, OSError, ValueError) as e:
            self.log_line(f"Receive loop ended: {e}")
        finally:
            self.root.after(0, self._on_server_drop)

    def _on_server_drop(self) -> None:
        if self.sock:
            self.log_line("Server connection closed or error.")
        self.disconnect()

    def _handle_broadcast(self, body: bytes) -> None:
        if len(body) < 4 + SHA3_512_DIGEST:
            self.log_line("Broadcast packet too short")
            return
        ln = struct.unpack_from("!I", body, 0)[0]
        ct = body[4 : 4 + ln]
        mac = body[4 + ln : 4 + ln + SHA3_512_DIGEST]
        if self.channel_hmac is None or self.channel_aes is None or self.channel_iv is None:
            return
        good = hmac_sha3_512(self.channel_hmac, ct)
        ok = secrets.compare_digest(good, mac)
        self.log_line(f"Broadcast HMAC verification: {'OK' if ok else 'FAIL'}")
        self.log_line(f"  expected: {good.hex()[:48]}...")
        self.log_line(f"  received: {mac.hex()[:48]}...")
        if not ok:
            self._ui_error("Message", "HMAC verification failed; message discarded.")
            return
        try:
            plain = aes_cbc_pkcs7_decrypt(self.channel_aes, self.channel_iv, ct)
            msg = plain.decode("utf-8", errors="replace")
        except Exception as e:
            self.log_line(f"Decryption error: {e}")
            self._ui_error("Message", "Cannot decrypt message.")
            return
        self.log_line(f"RECEIVED (plaintext): {msg}")

        def _append() -> None:
            self.incoming_text.configure(state="normal")
            self.incoming_text.insert("end", msg + "\n")
            self.incoming_text.see("end")
            self.incoming_text.configure(state="disabled")

        self.root.after(0, _append)

    def send_broadcast(self) -> None:
        if not self.sock or not self.authenticated:
            return
        text = self.msg_var.get()
        if not text:
            return
        threading.Thread(target=self._send_broadcast_worker, args=(text,), daemon=True).start()

    def _send_broadcast_worker(self, text: str) -> None:
        try:
            assert self.channel_aes and self.channel_iv and self.channel_hmac and self.sock
            pt = text.encode("utf-8")
            ct = aes_cbc_pkcs7_encrypt(self.channel_aes, self.channel_iv, pt)
            mac = hmac_sha3_512(self.channel_hmac, ct)
            blob = struct.pack("!I", len(ct)) + ct + mac
            self.log_line(f"SENT ciphertext_len={len(ct)}, HMAC (hex prefix)={mac.hex()[:32]}...")
            send_frame(self.sock, b"M" + blob)
        except Exception as e:
            self.log_line(f"Send error: {e}")
            self._ui_error("Send", str(e))

    def on_close(self) -> None:
        self.disconnect()
        self.root.destroy()


def main() -> None:
    root = tk.Tk()
    app = SecureClientApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()


if __name__ == "__main__":
    main()
