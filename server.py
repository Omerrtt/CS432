# -*- coding: utf-8 -*-
from __future__ import annotations

import hashlib
import hmac
import os
import queue
import secrets
import socket
import sqlite3
import struct
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
from typing import Any, Dict, Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend

# --- Constants ---
CHANNELS = ("IF100", "MATH101", "SPS101")
SHA3_512_DIGEST = 64
RSA_KEY_SIZE_BYTES = 384  # 3072 bits
MAX_FRAME = 16 * 1024 * 1024

# Protocol strings
MSG_ENROLL_OK = "SUCCESS"
MSG_ENROLL_ERR_USER = "ERROR:USERNAME_TAKEN"
MSG_AUTH_OK = "Authentication Successful"
MSG_AUTH_FAIL = "Authentication Unsuccessful"
MSG_CHANNEL_UNAVAILABLE = "Channel Unavailable"


# Normalize channel strings for DB/UI consistency (strip whitespace).
def normalize_channel(name: str) -> str:
    # Normalize DB/GUI channel strings so UI panels always match (strip whitespace).
    return name.strip()


# Parse a relayed broadcast packet (op "B") into (ciphertext, mac) for logging.
def parse_relay_wire_payload(packet: bytes) -> Optional[Tuple[bytes, bytes]]:
    # Parse client broadcast wire bytes:
    #   b'B' + u32_be(len_ct) + ciphertext + HMAC-SHA3-512(64B)
    if len(packet) < 1 + 4 + SHA3_512_DIGEST:
        return None
    if packet[:1] != b"B":
        return None
    inner = packet[1:]
    ln = struct.unpack_from("!I", inner, 0)[0]
    if ln < 0 or ln > MAX_FRAME:
        return None
    need = 4 + ln + SHA3_512_DIGEST
    if len(inner) < need:
        return None
    ct = inner[4 : 4 + ln]
    mac = inner[4 + ln : need]
    return ct, mac


 # Compute SHA3-512 digest for protocol-derived keys and hashes.
def sha3_512(data: bytes) -> bytes:
    return hashlib.sha3_512(data).digest()


 # Compute HMAC-SHA3-512 used for auth proof and message integrity.
def hmac_sha3_512(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha3_512).digest()


 # Derive AES key/IV from reversed-password hash for encrypting/decrypting auth ACKs.
def derive_password_side_keys_from_rev_hash(rev_hash: bytes) -> Tuple[bytes, bytes]:
    # Password-side (client/server) decrypt keys derived from SHA3-512(reversed_password):
    # - AES-256 key = first 32 bytes
    # - IV = next 16 bytes
    if len(rev_hash) != SHA3_512_DIGEST:
        raise ValueError("invalid rev_hash length")
    aes_key = rev_hash[:32]
    iv = rev_hash[32:48]
    return aes_key, iv


 # Derive per-channel AES/IV/HMAC keys from the server's master secret (KDF as per PDF).
def derive_channel_keys_from_master(master: str) -> Tuple[bytes, bytes, bytes]:
    # Per-channel symmetric keys derived from the server's master secret (PDF-aligned):
    # - AES-256 key + IV from SHA3-512(master)
    # - HMAC key from SHA3-512(reverse(master))[:32]
    m = master.encode("utf-8")
    h = sha3_512(m)
    aes_k = h[:32]
    iv = h[32:48]
    hr = sha3_512(m[::-1])
    hmac_k = hr[:32]
    return aes_k, iv, hmac_k


 # Encrypt using AES-256-CBC with PKCS7 padding.
def aes_cbc_pkcs7_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    padder = sym_padding.PKCS7(128).padder()
    data = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    return enc.update(data) + enc.finalize()


 # Decrypt AES-256-CBC with PKCS7 unpadding.
def aes_cbc_pkcs7_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


 # Read exactly N bytes from a TCP stream (or raise on disconnect).
def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf.extend(chunk)
    return bytes(buf)


 # Receive a length-prefixed frame (4B big-endian length + payload).
def recv_frame(sock: socket.socket) -> bytes:
    hdr = recv_exact(sock, 4)
    ln = struct.unpack("!I", hdr)[0]
    if ln > MAX_FRAME:
        raise ValueError("frame too large")
    return recv_exact(sock, ln)


 # Send a length-prefixed frame (4B big-endian length + payload).
def send_frame(sock: socket.socket, payload: bytes) -> None:
    sock.sendall(struct.pack("!I", len(payload)) + payload)


 # RSA sign using SHA3-512 (used for enrollment responses and auth ACK ciphertext).
def rsa_sign_sha3_512(priv: rsa.RSAPrivateKey, data: bytes) -> bytes:
    return priv.sign(data, padding.PKCS1v15(), hashes.SHA3_512())


 # Verify RSA signature using SHA3-512.
def rsa_verify_sha3_512(pub: rsa.RSAPublicKey, data: bytes, sig: bytes) -> None:
    pub.verify(sig, data, padding.PKCS1v15(), hashes.SHA3_512())


 # RSA encrypt enrollment plaintext (PKCS#1 v1.5 for compatibility with SHA3-only requirement).
def rsa_encrypt_pkcs1v15(pub: rsa.RSAPublicKey, plaintext: bytes) -> bytes:
    # cryptography does not support OAEP+SHA3-512; project only requires RSA encryption here.
    return pub.encrypt(plaintext, padding.PKCS1v15())


 # RSA decrypt enrollment ciphertext.
def rsa_decrypt_pkcs1v15(priv: rsa.RSAPrivateKey, ciphertext: bytes) -> bytes:
    return priv.decrypt(ciphertext, padding.PKCS1v15())


 # Build enrollment plaintext blob that will be RSA-encrypted.
def pack_enrollment_plaintext(username: str, channel: str, pwd_hash: bytes, rev_hash: bytes) -> bytes:
    u = username.encode("utf-8")
    c = channel.encode("utf-8")
    if len(pwd_hash) != 64 or len(rev_hash) != 64:
        raise ValueError("invalid hash length")
    if len(u) > 200 or len(c) > 32:
        raise ValueError("username or channel too long (watch RSA size limits)")
    return struct.pack("!H", len(u)) + u + struct.pack("!H", len(c)) + c + pwd_hash + rev_hash


# Parse the decrypted enrollment plaintext into fields.
def unpack_enrollment_plaintext(blob: bytes) -> Tuple[str, str, bytes, bytes]:
    off = 0
    lu = struct.unpack_from("!H", blob, off)[0]
    off += 2
    u = blob[off : off + lu].decode("utf-8")
    off += lu
    lc = struct.unpack_from("!H", blob, off)[0]
    off += 2
    ch = blob[off : off + lc].decode("utf-8")
    off += lc
    ph = blob[off : off + 64]
    off += 64
    rh = blob[off : off + 64]
    off += 64
    if off != len(blob):
        raise ValueError("trailing bytes in enrollment plaintext")
    return u, ch, ph, rh


class EnrollmentDB:
    # SQLite-backed enrollment database (username -> hashes + channel).
    # Initialize DB wrapper and ensure schema exists.
    def __init__(self, path: str) -> None:
        self.path = path
        self._init()

    # Create tables if missing.
    def _init(self) -> None:
        con = sqlite3.connect(self.path)
        try:
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS enrolled (
                    username TEXT PRIMARY KEY,
                    pwd_hash BLOB NOT NULL,
                    rev_hash BLOB NOT NULL,
                    channel TEXT NOT NULL
                )
                """
            )
            con.commit()
        finally:
            con.close()

    # Check whether a username is enrolled.
    def exists(self, username: str) -> bool:
        con = sqlite3.connect(self.path)
        try:
            r = con.execute("SELECT 1 FROM enrolled WHERE username = ?", (username.strip(),)).fetchone()
            return r is not None
        finally:
            con.close()

    # Insert a new enrolled user record.
    def insert(self, username: str, pwd_hash: bytes, rev_hash: bytes, channel: str) -> None:
        con = sqlite3.connect(self.path)
        try:
            con.execute(
                "INSERT INTO enrolled (username, pwd_hash, rev_hash, channel) VALUES (?,?,?,?)",
                (username.strip(), pwd_hash, rev_hash, normalize_channel(channel)),
            )
            con.commit()
        finally:
            con.close()

    # Fetch enrolled user's hashes and channel (or None).
    def get_user(self, username: str) -> Optional[Tuple[bytes, bytes, str]]:
        con = sqlite3.connect(self.path)
        try:
            r = con.execute(
                "SELECT pwd_hash, rev_hash, channel FROM enrolled WHERE username = ?", (username.strip(),)
            ).fetchone()
            if r is None:
                return None
            return r[0], r[1], normalize_channel(r[2])
        finally:
            con.close()


class ClientSession:
    # Connected socket + per-connection state (server worker thread).

    # Initialize per-connection session state.
    def __init__(self, sock: socket.socket, addr: Any, server: "SecureServerApp") -> None:
        self.sock = sock
        self.addr = addr
        self.server = server
        self.username: Optional[str] = None
        self.channel: Optional[str] = None
        self.authenticated = False
        self.send_lock = threading.Lock()

    # Log a line tagged with this connection's address.
    def log(self, text: str) -> None:
        self.server.log_line(f"[{self.addr}] {text}")

    # Thread-safe raw send of an already-framed payload.
    def send_raw(self, data: bytes) -> None:
        with self.send_lock:
            send_frame(self.sock, data)

    # Close the underlying socket (best-effort).
    def close(self) -> None:
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


class SecureServerApp:
    # Tkinter server app: maintains enrollment DB, auth sessions, and relays encrypted broadcasts.
    # Build the full server GUI and initialize state.
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        root.title("CS432/532 Secure Channel Server")
        self.log_q: "queue.Queue[str]" = queue.Queue()
        self.gui_log = scrolledtext.ScrolledText(root, height=10, width=100, state="disabled")
        self.gui_log.grid(row=0, column=0, columnspan=4, sticky="nsew", padx=6, pady=4)

        f_keys = ttk.LabelFrame(root, text="RSA PEM files (load on startup)")
        f_keys.grid(row=1, column=0, columnspan=4, sticky="ew", padx=6, pady=4)
        _base = os.path.dirname(os.path.abspath(__file__))
        self.path_enc_prv = tk.StringVar(value=os.path.join(_base, "server_enc_dec_pub_prv.pem"))
        self.path_sign_prv = tk.StringVar(
            value=os.path.join(_base, "server_sign_verify_prv.pem")
        )
        ttk.Label(f_keys, text="Encryption (enc/dec) private key:").grid(row=0, column=0, sticky="w")
        ttk.Entry(f_keys, textvariable=self.path_enc_prv, width=70).grid(row=0, column=1, padx=4)
        ttk.Button(f_keys, text="Browse...", command=self.browse_enc_prv).grid(row=0, column=2)
        ttk.Label(f_keys, text="Signing private key:").grid(row=1, column=0, sticky="w")
        ttk.Entry(f_keys, textvariable=self.path_sign_prv, width=70).grid(row=1, column=1, padx=4)
        ttk.Button(f_keys, text="Browse...", command=self.browse_sign_prv).grid(row=1, column=2)

        f_listen = ttk.LabelFrame(root, text="Listening")
        f_listen.grid(row=2, column=0, columnspan=4, sticky="ew", padx=6, pady=4)
        self.port_var = tk.StringVar(value="53000")
        ttk.Label(f_listen, text="Port:").grid(row=0, column=0)
        ttk.Entry(f_listen, textvariable=self.port_var, width=10).grid(row=0, column=1, padx=4)
        self.btn_start = ttk.Button(f_listen, text="Start Listening", command=self.start_listen)
        self.btn_start.grid(row=0, column=2, padx=6)
        self.btn_stop = ttk.Button(
            f_listen, text="Stop / Close Connections", command=self.stop_listen, state="disabled"
        )
        self.btn_stop.grid(row=0, column=3, padx=6)

        f_ms = ttk.LabelFrame(
            root, text="Channel master secret (Generate once; does not change while server runs)"
        )
        f_ms.grid(row=3, column=0, columnspan=4, sticky="ew", padx=6, pady=4)
        self.master_vars: Dict[str, tk.StringVar] = {}
        self.gen_flags: Dict[str, bool] = {c: False for c in CHANNELS}
        self.channel_keys: Dict[str, Dict[str, bytes]] = {c: {} for c in CHANNELS}
        col = 0
        for ch in CHANNELS:
            fr = ttk.Frame(f_ms)
            fr.grid(row=0, column=col, padx=8, pady=4, sticky="n")
            ttk.Label(fr, text=ch).pack()
            v = tk.StringVar()
            self.master_vars[ch] = v
            ttk.Entry(fr, textvariable=v, width=24, show="*").pack()
            ttk.Button(fr, text="Generate Key", command=lambda c=ch: self.generate_channel_keys(c)).pack(pady=2)
            col += 1

        # Compact layout for small screens: use tabs instead of stacking many panels vertically.
        nb = ttk.Notebook(root)
        nb.grid(row=4, column=0, columnspan=4, sticky="nsew", padx=6, pady=4)

        tab_online = ttk.Frame(nb)
        nb.add(tab_online, text="Online clients")
        self.online_list = scrolledtext.ScrolledText(tab_online, height=10, width=100, state="disabled", wrap="none")
        self.online_list.pack(fill="both", expand=True)

        self.channel_logs = {}
        for ch in CHANNELS:
            tab = ttk.Frame(nb)
            nb.add(tab, text=f"{ch} log")
            tx = scrolledtext.ScrolledText(tab, height=10, width=100, state="disabled", wrap="word")
            tx.pack(fill="both", expand=True)
            tx.configure(state="normal")
            tx.insert("end", "No messages yet.\n")
            tx.configure(state="disabled")
            self.channel_logs[ch] = tx

        # Make notebook expand with window resize.
        root.rowconfigure(4, weight=1)
        root.columnconfigure(0, weight=1)

        self.sock_listen: Optional[socket.socket] = None
        self.accept_thread: Optional[threading.Thread] = None
        self.running = False
        self.sessions_lock = threading.Lock()
        self.sessions: Dict[int, ClientSession] = {}
        self.online_users: Dict[str, ClientSession] = {}
        # Prevent concurrent login attempts for same username
        self.pending_auth_users: Dict[str, ClientSession] = {}

        self.priv_enc: Optional[rsa.RSAPrivateKey] = None
        self.priv_sign: Optional[rsa.RSAPrivateKey] = None

        self.db = EnrollmentDB(os.path.join(os.path.dirname(os.path.abspath(__file__)), "enrollments.sqlite"))

        self.root.after(120, self._drain_log_queue)

    # Pick server encryption private key PEM path.
    def browse_enc_prv(self) -> None:
        p = filedialog.askopenfilename(title="server_enc_dec_pub_prv.pem", filetypes=[("PEM", "*.pem"), ("All", "*.*")])
        if p:
            self.path_enc_prv.set(p)

    # Pick server signing private key PEM path.
    def browse_sign_prv(self) -> None:
        p = filedialog.askopenfilename(
            title="Signing private key (PEM)", filetypes=[("PEM", "*.pem"), ("All", "*.*")]
        )
        if p:
            self.path_sign_prv.set(p)

    # Load server RSA private keys from selected PEM files.
    def _load_rsa_keys(self) -> bool:
        pe = self.path_enc_prv.get().strip()
        ps = self.path_sign_prv.get().strip()
        if not pe or not ps:
            messagebox.showerror("Error", "Please select both PEM file paths.")
            return False
        try:
            with open(pe, "rb") as f:
                self.priv_enc = serialization.load_pem_private_key(f.read(), password=None)
            with open(ps, "rb") as f:
                self.priv_sign = serialization.load_pem_private_key(f.read(), password=None)
        except Exception as e:
            messagebox.showerror("PEM", f"Failed to load key: {e}")
            return False
        assert isinstance(self.priv_enc, rsa.RSAPrivateKey)
        assert isinstance(self.priv_sign, rsa.RSAPrivateKey)
        self.log_line(
            "RSA private keys loaded; public/private summary below (hex, required for grading visibility)."
        )
        for label, pk in (("Encryption (enc/dec)", self.priv_enc), ("Signing", self.priv_sign)):
            pubn = pk.public_key().public_numbers()
            prv = pk.private_numbers()
            self.log_line(f"{label} public n (hex, prefix): {hex(pubn.n)[:130]}...")
            self.log_line(f"{label} public e: {pubn.e}")
            self.log_line(f"{label} private d (hex, prefix): {hex(prv.d)[:130]}...")
        return True

    # Enqueue a line to append to the GUI log.
    def log_line(self, s: str) -> None:
        self.log_q.put(s)

    # Drain queued log lines into the GUI text widget.
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
        self.root.after(120, self._drain_log_queue)

    # Refresh the "Online clients" tab from current server state.
    def _set_online_widget(self) -> None:
        self.online_list.configure(state="normal")
        self.online_list.delete("1.0", "end")
        with self.sessions_lock:
            for u, se in self.online_users.items():
                self.online_list.insert("end", f"{u} -> {se.channel} {se.addr}\n")
        self.online_list.configure(state="disabled")

    # Generate per-channel AES/IV/HMAC keys from a master secret (one-time per run).
    def generate_channel_keys(self, channel: str) -> None:
        if self.gen_flags[channel]:
            messagebox.showinfo("Info", f"{channel} keys were already generated (must not change while server runs).")
            return
        ms = self.master_vars[channel].get()
        if not ms:
            messagebox.showerror("Error", "Please enter a master secret.")
            return
        aes_k, iv, hmac_k = derive_channel_keys_from_master(ms)
        self.channel_keys[channel] = {"aes": aes_k, "iv": iv, "hmac": hmac_k}
        self.gen_flags[channel] = True
        self.log_line(f"--- {channel} channel keys generated ---")
        self.log_line(f"{channel} AES-256 key (hex): {aes_k.hex()}")
        self.log_line(f"{channel} IV (hex): {iv.hex()}")
        self.log_line(f"{channel} HMAC key (hex): {hmac_k.hex()}")
        self.log_line(f"Master SHA3-512 (hex, prefix): {sha3_512(ms.encode()).hex()[:64]}...")

    # Start TCP listener and accept loop.
    def start_listen(self) -> None:
        if not self._load_rsa_keys():
            return
        try:
            port = int(self.port_var.get().strip())
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid port.")
            return
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", port))
            s.listen(50)
        except OSError as e:
            messagebox.showerror("Socket", str(e))
            return
        self.sock_listen = s
        self.running = True
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self.accept_thread.start()
        self.log_line(f"Listening on: 0.0.0.0:{port} (TCP)")

    # Stop listener and close all active client sockets.
    def stop_listen(self) -> None:
        self.running = False
        if self.sock_listen:
            try:
                self.sock_listen.close()
            except OSError:
                pass
            self.sock_listen = None
        with self.sessions_lock:
            sessions = list(self.sessions.values())
            self.sessions.clear()
            self.online_users.clear()
            self.pending_auth_users.clear()
        for se in sessions:
            se.close()
        self._set_online_widget()
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self.log_line("Server stopped listening; all client sockets were closed.")

    # Accept incoming TCP connections in a background thread.
    def _accept_loop(self) -> None:
        assert self.sock_listen is not None
        while self.running:
            try:
                conn, addr = self.sock_listen.accept()
            except OSError:
                break
            t = threading.Thread(target=self._client_worker, args=(conn, addr), daemon=True)
            t.start()

    # Track a new session and update online widget.
    def register_session(self, sid: int, session: ClientSession) -> None:
        with self.sessions_lock:
            self.sessions[sid] = session
        self.root.after(0, self._set_online_widget)

    # Remove a session from tracking and update online widget.
    def unregister_session(self, sid: int) -> None:
        with self.sessions_lock:
            self.sessions.pop(sid, None)
            to_del = [u for u, se in self.online_users.items() if id(se) == sid]
            for u in to_del:
                del self.online_users[u]
        self.root.after(0, self._set_online_widget)

    # Mark a user as online after successful authentication.
    def add_online(self, username: str, session: ClientSession) -> None:
        with self.sessions_lock:
            self.online_users[username] = session
        self.root.after(0, self._set_online_widget)

    # Remove an online user (disconnect/cleanup).
    def remove_online_user(self, username: str) -> None:
        with self.sessions_lock:
            self.online_users.pop(username, None)
        self.root.after(0, self._set_online_widget)

    # Append an encrypted relay summary to the per-channel log tab.
    def append_channel_traffic_log(self, channel: str, text: str) -> None:
        key = normalize_channel(channel)

        # UI update closure (run on Tk thread).
        # Append to the channel tab and keep the view scrolled to the end.
        def _w() -> None:
            w = self.channel_logs.get(key)
            if w is None:
                return
            w.configure(state="normal")
            if w.get("1.0", "end").strip() == "No messages yet.":
                w.delete("1.0", "end")
            w.insert("end", text)
            if not text.endswith("\n"):
                w.insert("end", "\n")
            w.see("end")
            w.configure(state="disabled")

        self.root.after(0, _w)

    # Relay an encrypted broadcast to all authenticated clients in the same channel.
    def relay_broadcast(self, from_session: ClientSession, packet: bytes) -> None:
        ch = normalize_channel(from_session.channel or "")
        if not ch:
            return
        u = (from_session.username or "").strip()
        with self.sessions_lock:
            targets = [
                se for se in self.sessions.values() if se.authenticated and normalize_channel(se.channel or "") == ch
            ]
        names = sorted({(se.username or "").strip() for se in targets if se.username})
        relay_to = ", ".join(names) if names else "(none)"
        parsed = parse_relay_wire_payload(packet)
        if parsed is not None:
            ct, mac = parsed
            block = (
                f"Received encrypted packet from {u}\n"
                f"Ciphertext (prefix): {ct.hex()[:16]}... (len={len(ct)} bytes)\n"
                f"HMAC (prefix): {mac.hex()[:16]}...\n"
                f"Relayed to: {relay_to}\n"
                f"Server did not decrypt or verify this message.\n"
                f"---\n"
            )
        else:
            block = (
                f"Received broadcast from {u} (unparsed wire layout; raw_len={len(packet)} bytes)\n"
                f"Relayed to: {relay_to}\n"
                f"---\n"
            )
        self.append_channel_traffic_log(ch, block)
        for se in targets:
            try:
                se.send_raw(packet)
            except Exception as e:
                self.log_line(f"Relay error {se.addr}: {e}")

    # --- Protocol handling ---

    # Per-client worker: receive frames and dispatch protocol handlers.
    def _client_worker(self, conn: socket.socket, addr: Any) -> None:
        session = ClientSession(conn, addr, self)
        sid = id(session)
        self.register_session(sid, session)
        session.log("New connection")
        try:
            while True:
                frame = recv_frame(conn)
                op = frame[:1]
                body = frame[1:]
                if op == b"E":
                    self._handle_enroll(session, body)
                elif op == b"A":
                    self._handle_auth(session, body)
                elif op == b"M":
                    self._handle_message(session, body)
                elif op == b"X":
                    break
                else:
                    session.log("Unknown op code")
                    break
        except (ConnectionError, ValueError, OSError) as e:
            session.log(f"Connection ended: {e}")
        finally:
            if session.username:
                with self.sessions_lock:
                    self.pending_auth_users.pop(session.username.strip(), None)
            if session.username and session.authenticated:
                self.remove_online_user(session.username.strip())
            self.unregister_session(sid)
            session.close()
            session.log("Socket closed")

    # Handle enrollment request (RSA-decrypt, store in SQLite, return signed response).
    def _handle_enroll(self, session: ClientSession, rsa_cipher: bytes) -> None:
        assert self.priv_enc is not None and self.priv_sign is not None
        try:
            plain = rsa_decrypt_pkcs1v15(self.priv_enc, rsa_cipher)
            username, channel, pwd_h, rev_h = unpack_enrollment_plaintext(plain)
            username = username.strip()
            channel = normalize_channel(channel)
        except Exception as e:
            self.log_line(f"Enrollment parse/decrypt failed: {e}")
            reply = MSG_ENROLL_ERR_USER.encode()  # generic failure still signed
            sig = rsa_sign_sha3_512(self.priv_sign, reply)
            session.send_raw(b"R" + struct.pack("!H", len(reply)) + reply + sig)
            return
        if channel not in CHANNELS:
            txt = (MSG_ENROLL_ERR_USER + ":BAD_CHANNEL").encode()
            sig = rsa_sign_sha3_512(self.priv_sign, txt)
            session.send_raw(b"R" + struct.pack("!H", len(txt)) + txt + sig)
            session.log("Invalid channel")
            return
        if self.db.exists(username):
            reply = MSG_ENROLL_ERR_USER.encode()
            sig = rsa_sign_sha3_512(self.priv_sign, reply)
            session.send_raw(b"R" + struct.pack("!H", len(reply)) + reply + sig)
            session.log(f"Enrollment rejected (username exists): {username}")
            return
        try:
            self.db.insert(username, pwd_h, rev_h, channel)
        except sqlite3.IntegrityError:
            reply = MSG_ENROLL_ERR_USER.encode()
            sig = rsa_sign_sha3_512(self.priv_sign, reply)
            session.send_raw(b"R" + struct.pack("!H", len(reply)) + reply + sig)
            return
        reply = MSG_ENROLL_OK.encode()
        sig = rsa_sign_sha3_512(self.priv_sign, reply)
        session.send_raw(b"R" + struct.pack("!H", len(reply)) + reply + sig)
        self.log_line(f"Enrollment OK: {username} channel={channel}")
        self.log_line(f"  pwd_hash (hex): {pwd_h.hex()}")
        self.log_line(f"  rev_pwd_hash (hex): {rev_h.hex()}")

    # Handle authentication handshake steps (A1 username -> challenge, A2 HMAC -> signed ACK).
    def _handle_auth(self, session: ClientSession, body: bytes) -> None:
        # `body` = sub-op byte + payload (multiple auth steps share the same op code).
        assert self.priv_enc is not None and self.priv_sign is not None
        if len(body) < 1:
            return
        sub = body[0:1]
        rest = body[1:]
        if sub == b"1":
            # auth hello: UTF-8 username
            username = rest.decode("utf-8").strip()
            row = self.db.get_user(username)
            if row is None:
                challenge = secrets.token_bytes(16)
                session.username = username
                session.channel = None
                session._challenge = challenge  # type: ignore
                # Not enrolled: HMAC won't match; use random rev_hash so client can't decrypt ACK
                session._pwd_hash = secrets.token_bytes(64)  # type: ignore
                session._rev_hash = secrets.token_bytes(64)  # type: ignore
                session._enrolled = False  # type: ignore
                session.send_raw(b"C" + challenge)
                session.log(f"Unenrolled user (challenge sent): {username}")
                self.log_line(f"Auth challenge (not enrolled) -> {username}: {challenge.hex()}")
                return
            pwd_h, rev_h, channel = row
            with self.sessions_lock:
                if username in self.online_users:
                    self._send_auth_ack_encrypted_signed(session, rev_h, (MSG_AUTH_FAIL + "\n").encode("utf-8"))
                    session.log(f"Same username already online: {username}")
                    return
                if username in self.pending_auth_users:
                    self._send_auth_ack_encrypted_signed(session, rev_h, (MSG_AUTH_FAIL + "\n").encode("utf-8"))
                    session.log(f"Another login attempt is already in progress for: {username}")
                    return
                self.pending_auth_users[username] = session
            challenge = secrets.token_bytes(16)
            session.username = username
            session.channel = channel
            session._challenge = challenge  # type: ignore
            session._rev_hash = rev_h  # type: ignore
            session._pwd_hash = pwd_h  # type: ignore
            session._enrolled = True  # type: ignore
            session.send_raw(b"C" + challenge)
            self.log_line(f"Auth challenge -> {username}: {challenge.hex()}")
            return
        if sub == b"2":
            if not getattr(session, "_challenge", None) or session.username is None:
                return
            uname = session.username.strip()
            client_hmac = rest
            pwd_h = session._pwd_hash  # type: ignore
            rev_h = session._rev_hash  # type: ignore
            key = pwd_h[:32]
            good = hmac_sha3_512(key, session._challenge)  # type: ignore
            ok = secrets.compare_digest(good, client_hmac)
            self.log_line(f"HMAC verification ({uname}): {'SUCCESS' if ok else 'FAIL'}")
            self.log_line(f"  expected HMAC (hex): {good.hex()}")
            self.log_line(f"  received HMAC (hex): {client_hmac.hex()}")
            if not ok:
                fail_plain = (MSG_AUTH_FAIL + "\n").encode("utf-8")
                self._send_auth_ack_encrypted_signed(session, rev_h, fail_plain)
                with self.sessions_lock:
                    self.pending_auth_users.pop(uname, None)
                return
            if not getattr(session, "_enrolled", False) or session.channel is None:
                fail_plain = (MSG_AUTH_FAIL + "\n").encode("utf-8")
                self._send_auth_ack_encrypted_signed(session, rev_h, fail_plain)
                with self.sessions_lock:
                    self.pending_auth_users.pop(uname, None)
                return
            ch = normalize_channel(session.channel)
            assert ch is not None
            if not self.gen_flags.get(ch):
                outer_plain = (MSG_CHANNEL_UNAVAILABLE + "\n").encode("utf-8")
                self._send_auth_ack_encrypted_signed(session, session._rev_hash, outer_plain)
                self.log_line(f"Channel not ready: {ch}")
                with self.sessions_lock:
                    self.pending_auth_users.pop(uname, None)
                return
            ck = self.channel_keys[ch]
            chb = ch.encode("utf-8")
            inner_plain = ck["aes"] + ck["iv"] + ck["hmac"] + struct.pack("!H", len(chb)) + chb
            # Success ACK plaintext = "Authentication Successful\n" + channel key material blob.
            # This whole plaintext is encrypted once (AES-CBC) and the ciphertext is RSA-signed in
            # `_send_auth_ack_encrypted_signed`.
            outer_plain = MSG_AUTH_OK.encode("utf-8") + b"\n" + inner_plain
            self._send_auth_ack_encrypted_signed(session, session._rev_hash, outer_plain)
            session.authenticated = True
            session.channel = ch
            with self.sessions_lock:
                self.pending_auth_users.pop(uname, None)
            self.add_online(uname, session)
            self.log_line(f"Authenticated: {uname} ({ch})")
            return

    # Encrypt auth ACK with AES-CBC and sign ciphertext with RSA (sent as op "K").
    def _send_auth_ack_encrypted_signed(self, session: ClientSession, rev_hash: bytes, outer_plain: bytes) -> None:
        assert self.priv_sign is not None
        aes_k, iv = derive_password_side_keys_from_rev_hash(rev_hash)
        outer_cipher = aes_cbc_pkcs7_encrypt(aes_k, iv, outer_plain)
        sig = rsa_sign_sha3_512(self.priv_sign, outer_cipher)
        session.send_raw(b"K" + outer_cipher + sig)

    # Handle a secure message send (relay as broadcast to same channel).
    def _handle_message(self, session: ClientSession, packet: bytes) -> None:
        if not session.authenticated or not session.channel:
            return
        self.relay_broadcast(session, b"B" + packet)


# Server GUI entrypoint.
def main() -> None:
    root = tk.Tk()
    app = SecureServerApp(root)

    # Window close handler.
    def on_close() -> None:
        app.stop_listen()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()


if __name__ == "__main__":
    main()
