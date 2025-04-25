from mitmproxy import http, ctx, addonmanager
from urllib.parse import urlparse, parse_qs, urlencode
import sqlite3
import base64
import os
import json
import subprocess

class Reflector:
    def __init__(self):
        self.target_domain = ""
        self.db_path = ""

    def load(self, loader: addonmanager.Loader):
        loader.add_option(
            name="reflector_target",
            typespec=str,
            default="",
            help="Target domain for reflection scanning (e.g., example.com)",
        )

    def configure(self, updated):
        self.target_domain = ctx.options.reflector_target
        if not self.target_domain:
            ctx.log.error("reflector_target must be specified via --set.")
            return

        safe_name = self.target_domain.replace('.', '_')
        self.db_path = f"/tmp/scan_jobs_{safe_name}.db"
        self._init_db()
        ctx.log.info(f"Reflector DB initialized for domain: {self.target_domain}")
        print("success configure reflector")

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
                body TEXT,
                status TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(host, path) -- Ensure host and path combination is unique
            )
        ''')
        conn.commit()
        conn.close()

    def request(self, flow: http.HTTPFlow):
        parsed = urlparse(flow.request.pretty_url)
        if not parsed.hostname or not parsed.hostname.endswith(self.target_domain):
            return

        method = flow.request.method
        host = parsed.hostname
        port = parsed.port if parsed.port else (443 if parsed.scheme == 'https' else 80)
        path = parsed.path
        query = parsed.query
        headers = dict(flow.request.headers)
        body = flow.request.get_text()

        # Combine all cookie headers into a single string separated by "; "
        if "cookie" in headers:
            cookies = []
            for key, value in flow.request.headers.items():
                if key.lower() == "cookie":
                    # Replace ", " with "; " in the cookie string
                    value = value.decode("utf-8") if isinstance(value, bytes) else value
                    cookies.append(value.replace(", ", "; "))
            headers["cookie"] = "; ".join(cookies)

        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()

            # Check if the host and path combination already exists
            c.execute('SELECT query FROM jobs WHERE host = ? AND path = ?', (host, path))
            existing_query = c.fetchone()

            if existing_query:
                existing_query_dict = parse_qs(existing_query[0])
                new_query_dict = parse_qs(query)

                # Check if the new query is the same as the existing query
                if existing_query_dict == new_query_dict:
                    return

                # Merge the existing query parameters with the new ones
                merged_query = {**existing_query_dict, **new_query_dict}
                merged_query_str = urlencode(merged_query, doseq=True)

                # Update the existing record with the merged query
                c.execute('''
                    UPDATE jobs
                    SET query = ?, headers = ?, body = ?, status = 'queued', timestamp = CURRENT_TIMESTAMP
                    WHERE host = ? AND path = ?
                ''', (
                    merged_query_str,
                    json.dumps(headers),
                    body,
                    host,
                    path
                ))
                ctx.log.info(f"[UPDATED] {flow.request.pretty_url}")
            else:
                # Insert a new record
                c.execute('''
                    INSERT INTO jobs (method, host, port, path, query, headers, body, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    method,
                    host,
                    port,
                    path,
                    query,
                    json.dumps(headers),
                    body,
                    "queued"
                ))
                ctx.log.info(f"[ENQUEUED] {flow.request.pretty_url}")

            conn.commit()
            conn.close()
        except Exception as e:
if __name__ == "__main__":f"[DB ERROR] {str(e)}")
    print("Usage: mitmproxy --scripts reflector.py --set reflector_target=facebook.com")
    sys.exit(0)
    Reflector()
]

if __name__ == "__main__":
    print("Usage: mitmproxy --scripts reflector.py --set reflector_target=facebook.com")
    sys.exit(0)
