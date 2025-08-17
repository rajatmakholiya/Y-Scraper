#!/usr/bin/env python3
"""
backend/app.py

Flask REST API backend for Video Downloader (server-stored downloads).
Do NOT use this to bypass DRM or platform restrictions. Use only with
video sources you own or are permitted to download.

Requires:
  pip install -r requirements.txt
  ffmpeg available on PATH for HLS -> mp4 remuxing.
"""
import os
import re
import time
import json
import sqlite3
import shutil
import tempfile
import subprocess
from functools import wraps
from urllib.parse import urljoin, urlparse

import requests
from flask import (
    Flask, request, jsonify, send_file, abort, g
)
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required,
    get_jwt_identity
)

# -------------------- Load config --------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
ENV_PATH = os.path.join(BASE_DIR, ".env")
if os.path.exists(ENV_PATH):
    load_dotenv(ENV_PATH)

SECRET_KEY = os.getenv("SECRET_KEY", "change-me")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "change-me-too")
DATABASE = os.getenv("DATABASE", os.path.join(BASE_DIR, "app.db"))
DOWNLOAD_ROOT = os.getenv("DOWNLOAD_ROOT", os.path.join(BASE_DIR, "downloads"))
MAX_TOTAL_DOWNLOAD_MB = int(os.getenv("MAX_TOTAL_DOWNLOAD_MB", "2048"))
MIN_SECONDS_BETWEEN_JOBS = int(os.getenv("MIN_SECONDS_BETWEEN_JOBS", "5"))
CHUNK_SIZE = int(os.getenv("CHUNK_SIZE", str(1 * 1024 * 1024)))  # 1 MB

os.makedirs(DOWNLOAD_ROOT, exist_ok=True)

# -------------------- Flask app --------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY
app.config["JWT_SECRET_KEY"] = JWT_SECRET_KEY
app.config["PROPAGATE_EXCEPTIONS"] = True

jwt = JWTManager(app)

# -------------------- DB helpers --------------------
SCHEMA_SQL = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS downloads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    url TEXT NOT NULL,
    title TEXT NOT NULL,
    filepath TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);
"""

def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        db = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
        g._db = db
    return db

@app.teardown_appcontext
def close_db(exc):
    db = getattr(g, "_db", None)
    if db:
        db.close()

def init_db():
    db = get_db()
    db.executescript(SCHEMA_SQL)
    db.commit()

def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

def execute_db(query, args=()):
    cur = get_db().execute(query, args)
    get_db().commit()
    return cur.lastrowid

@app.before_first_request
def _startup():
    init_db()

# -------------------- Utilities --------------------
def human_size(num_bytes: int) -> str:
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if num_bytes < 1024.0:
            return f"{num_bytes:.2f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.2f} PB"

def safe_title_from_url(url: str) -> str:
    parsed = urlparse(url)
    base = os.path.basename(parsed.path) or "download"
    base = re.sub(r"[^A-Za-z0-9._-]+", "_", base)
    return base[:120] or "download"

def head_probe(url: str, timeout=15):
    """Return (content_type, content_length or None)"""
    try:
        resp = requests.head(url, allow_redirects=True, timeout=timeout)
        ct = resp.headers.get("Content-Type", "").lower()
        cl = resp.headers.get("Content-Length")
        return ct, int(cl) if cl and cl.isdigit() else None
    except Exception:
        # fallback to GET
        resp = requests.get(url, allow_redirects=True, stream=True, timeout=timeout)
        ct = resp.headers.get("Content-Type", "").lower()
        cl = resp.headers.get("Content-Length")
        resp.close()
        return ct, int(cl) if cl and cl.isdigit() else None

def ensure_ffmpeg_available():
    from shutil import which
    if which("ffmpeg") is None:
        raise RuntimeError("ffmpeg is required but not found in PATH. Please install ffmpeg.")

# -------------------- HLS helpers --------------------
HLS_STREAM_RE = re.compile(r"#EXT-X-STREAM-INF:([^\n]+)\n([^\n]+)")
ATTR_RE = re.compile(r'([A-Z0-9\-]+)=([^,]+)')

def parse_master_playlist(text: str, base_url: str):
    variants = []
    for match in HLS_STREAM_RE.finditer(text):
        attrs_line = match.group(1)
        rel_uri = match.group(2).strip()
        attrs = {k: v.strip().strip('"') for k, v in ATTR_RE.findall(attrs_line)}
        bw = int(attrs.get("BANDWIDTH", "0"))
        res = attrs.get("RESOLUTION")
        width = height = 0
        if res and "x" in res:
            try:
                width, height = map(int, res.lower().split("x"))
            except Exception:
                width = height = 0
        abs_uri = urljoin(base_url, rel_uri)
        variants.append({
            "url": abs_uri,
            "bandwidth": bw,
            "width": width,
            "height": height,
        })
    return variants

def pick_best_variant(variants):
    if not variants:
        return None
    return sorted(variants, key=lambda v: (v.get("height", 0), v.get("bandwidth", 0)), reverse=True)[0]

def download_hls_to_mp4(master_url: str, out_dir: str, title_hint: str) -> str:
    ensure_ffmpeg_available()
    r = requests.get(master_url, timeout=20)
    r.raise_for_status()
    master_text = r.text
    variants = parse_master_playlist(master_text, master_url)
    best = pick_best_variant(variants)
    if not best:
        raise RuntimeError("No HLS variants found in master playlist.")
    var_url = best["url"]
    rv = requests.get(var_url, timeout=20)
    rv.raise_for_status()
    variant_text = rv.text

    work_dir = tempfile.mkdtemp(prefix="hls_", dir=out_dir)
    local_playlist_path = os.path.join(work_dir, "playlist.m3u8")
    base_var = var_url

    segment_files = []
    local_lines = ["#EXTM3U\n"]
    for line in variant_text.splitlines(True):
        if line.startswith("#EXTINF"):
            local_lines.append(line)
        elif line.startswith("#"):
            local_lines.append(line)
        elif line.strip():
            seg_url = urljoin(base_var, line.strip())
            seg_name = f"seg_{len(segment_files):06d}.ts"
            seg_path = os.path.join(work_dir, seg_name)
            with requests.get(seg_url, stream=True, timeout=20) as seg_resp:
                seg_resp.raise_for_status()
                with open(seg_path, "wb") as f:
                    for chunk in seg_resp.iter_content(chunk_size=CHUNK_SIZE):
                        if chunk:
                            f.write(chunk)
            segment_files.append(seg_path)
            local_lines.append(seg_name + "\n")

    with open(local_playlist_path, "w", encoding="utf-8") as f:
        f.writelines(local_lines)

    safe_title = os.path.splitext(safe_title_from_url(title_hint))[0]
    out_mp4 = os.path.join(out_dir, f"{safe_title}.mp4")

    cmd = [
        "ffmpeg", "-y",
        "-allowed_extensions", "ALL",
        "-i", local_playlist_path,
        "-c", "copy",
        out_mp4,
    ]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode != 0:
        shutil.rmtree(work_dir, ignore_errors=True)
        raise RuntimeError(f"ffmpeg failed: {proc.stderr.decode(errors='ignore')}")
    shutil.rmtree(work_dir, ignore_errors=True)
    return out_mp4

# -------------------- MP4 direct download --------------------
def detect_url_kind(url: str):
    ct, _ = head_probe(url)
    if url.lower().endswith(".m3u8") or "application/vnd.apple.mpegurl" in ct or "application/x-mpegurl" in ct:
        return "hls"
    if url.lower().endswith(".mp4") or ct.startswith("video/mp4"):
        return "mp4"
    return "unknown"

def download_mp4(url: str, out_dir: str, title_hint: str, max_mb=MAX_TOTAL_DOWNLOAD_MB) -> str:
    safe_title = os.path.splitext(safe_title_from_url(title_hint))[0]
    out_path_tmp = os.path.join(out_dir, f"{safe_title}.mp4.part")
    out_path = os.path.join(out_dir, f"{safe_title}.mp4")
    ct, size = head_probe(url)
    if size and size > max_mb * 1024 * 1024:
        raise RuntimeError(f"File too large ({human_size(size)}). Limit is {max_mb} MB.")
    downloaded = 0
    headers = {}
    if os.path.exists(out_path_tmp):
        downloaded = os.path.getsize(out_path_tmp)
        headers["Range"] = f"bytes={downloaded}-"
    with requests.get(url, stream=True, headers=headers, timeout=30) as resp:
        resp.raise_for_status()
        mode = "ab" if downloaded else "wb"
        with open(out_path_tmp, mode) as f:
            for chunk in resp.iter_content(chunk_size=CHUNK_SIZE):
                if chunk:
                    f.write(chunk)
    os.replace(out_path_tmp, out_path)
    return out_path

# -------------------- Auth helpers --------------------
def get_user_by_email(email):
    return query_db("SELECT * FROM users WHERE email = ?", (email,), one=True)

# -------------------- API endpoints --------------------
@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    if not email or not password:
        return jsonify({"error": "email and password are required"}), 400
    if get_user_by_email(email):
        return jsonify({"error": "email already exists"}), 400
    pwd_hash = generate_password_hash(password)
    user_id = execute_db(
        "INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)",
        (email, pwd_hash, int(time.time()))
    )
    access_token = create_access_token(identity=user_id)
    return jsonify({"access_token": access_token, "user_id": user_id}), 201

@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    row = get_user_by_email(email)
    if not row or not check_password_hash(row["password_hash"], password):
        return jsonify({"error": "invalid credentials"}), 401
    access_token = create_access_token(identity=row["id"])
    return jsonify({"access_token": access_token, "user_id": row["id"]}), 200

@app.route("/api/recent", methods=["GET"])
@jwt_required()
def api_recent():
    user_id = get_jwt_identity()
    rows = query_db("SELECT id, url, title, filepath, size_bytes, created_at FROM downloads WHERE user_id = ? ORDER BY id DESC LIMIT 50", (user_id,))
    items = []
    for r in rows:
        items.append({
            "id": r["id"],
            "url": r["url"],
            "title": r["title"],
            "size_bytes": r["size_bytes"],
            "created_at": r["created_at"],
        })
    return jsonify({"downloads": items})

@app.route("/api/download", methods=["POST"])
@jwt_required()
def api_download():
    user_id = get_jwt_identity()
    payload = request.get_json() or {}
    url = (payload.get("url") or "").strip()
    if not url:
        return jsonify({"error": "url is required"}), 400

    # rate-limit per JWT session (simple, stored in DB not required; use query)
    last_row = query_db("SELECT created_at FROM downloads WHERE user_id = ? ORDER BY created_at DESC LIMIT 1", (user_id,), one=True)
    if last_row:
        last_ts = last_row["created_at"]
        if time.time() - last_ts < MIN_SECONDS_BETWEEN_JOBS:
            return jsonify({"error": f"Please wait {MIN_SECONDS_BETWEEN_JOBS} seconds between downloads."}), 429

    user_dir = os.path.join(DOWNLOAD_ROOT, f"user_{user_id}")
    os.makedirs(user_dir, exist_ok=True)

    try:
        kind = detect_url_kind(url)
        title_hint = url
        if kind == "mp4":
            out_path = download_mp4(url, user_dir, title_hint)
        elif kind == "hls":
            out_path = download_hls_to_mp4(url, user_dir, title_hint)
        else:
            return jsonify({"error": "Unsupported URL type. Only direct MP4 or non-DRM HLS (.m3u8) are supported."}), 400

        size = os.path.getsize(out_path)
        dl_id = execute_db(
            "INSERT INTO downloads (user_id, url, title, filepath, size_bytes, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (user_id, url, os.path.basename(out_path), out_path, size, int(time.time()))
        )
        return jsonify({
            "id": dl_id,
            "title": os.path.basename(out_path),
            "size_bytes": size,
            "download_url": f"/api/file/{dl_id}"
        }), 201

    except Exception as e:
        return jsonify({"error": f"Download failed: {str(e)}"}), 500

@app.route("/api/file/<int:download_id>", methods=["GET"])
@jwt_required()
def api_file(download_id):
    user_id = get_jwt_identity()
    row = query_db("SELECT * FROM downloads WHERE id = ? AND user_id = ?", (download_id, user_id), one=True)
    if not row:
        return abort(404)
    path = row["filepath"]
    if not os.path.exists(path):
        return abort(404)
    return send_file(path, as_attachment=True, download_name=row["title"])

# -------------------- Run --------------------
if __name__ == "__main__":
    # dev server
    app.run(host="0.0.0.0", port=5000, debug=True)
