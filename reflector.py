from mitmproxy import http, ctx, addonmanager
from urllib.parse import urlparse, parse_qs
import sqlite3
import base64
import os
import json

class Reflector:
    def __init__(self):
        self.allowed_domain = ""
        self.db_path = ""

    def load(self, loader: addonmanager.Loader):
        loader.add_option(
            name="reflector_target",
            typespec=str,
            default="",
            help="Target domain for reflection scanning (e.g., example.com)",
        )

    def configure(self, updated):
        self.allowed_domain = ctx.options.reflector_target
        if not self.allowed_domain:
            ctx.log.error("reflector_target must be specified via --set.")
            return

        safe_name = self.allowed_domain.replace('.', '_')
        self.db_path = f"/tmp/scan_jobs_{safe_name}.db"
        self._init_db()
        ctx.log.info(f"Reflector DB initialized for domain: {self.allowed_domain}")

    def _init_db(self):
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                method TEXT,
                host TEXT,
                port INTEGER,
                path TEXT,
                query TEXT,
                headers TEXT,
                cookies TEXT,
                body TEXT,
                status TEXT DEFAULT 'queued',
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        conn.close()

    def request(self, flow: http.HTTPFlow):
        parsed = urlparse(flow.request.pretty_url)
        if not parsed.hostname or not parsed.hostname.endswith(self.allowed_domain):
            return

        method = flow.request.method
        host = parsed.hostname
        port = parsed.port if parsed.port else (443 if parsed.scheme == 'https' else 80)
        path = parsed.path
        query = parsed.query
        headers = dict(flow.request.headers)
        cookies = dict(flow.request.cookies.fields)
        body = flow.request.get_text()

        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute('''
                INSERT INTO jobs (method, host, port, path, query, headers, cookies, body)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                method,
                host,
                port,
                path,
                query,
                json.dumps(headers),
                json.dumps(cookies),
                body
            ))
            conn.commit()
            conn.close()
            ctx.log.info(f"[ENQUEUED] {flow.request.pretty_url}")
        except Exception as e:
            ctx.log.error(f"[DB ERROR] {str(e)}")

addons = [
    Reflector()
]
