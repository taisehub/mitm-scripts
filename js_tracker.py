from mitmproxy import http, ctx
import sys
import os
from urllib.parse import urlparse, unquote
import pathlib
import subprocess

class JsTracker:
    def __init__(self):
        self.allowed_domains = set()

    def configure(self, updated):
        domains = ctx.options.js_tracker_domains
        self.allowed_domains = set(domain.strip() for domain in domains.split(",") if domain.strip())
        print("success configure js_tracker")

    def response(self, flow: http.HTTPFlow) -> None:
        url = flow.request.pretty_url
        parsed = urlparse(url)
        if not self.is_allowed_domain(parsed.hostname):
            return

        if not parsed.path.endswith(".js"):
            return

        if not flow.response.content:
            return

        raw_path = unquote(parsed.path.lstrip("/"))
        full_path = os.path.join(parsed.hostname, raw_path)

        # UTF-8 長の上限のためファイル名を短くする
        safe_path = self.trim_filename_to_bytes(full_path)

        os.makedirs(os.path.dirname(safe_path), exist_ok=True)

        content_bytes = flow.response.content
        content_text = content_bytes.decode("utf-8", errors="replace")

        with open(safe_path, "w", encoding="utf-8") as f:
            f.write(content_text)
        subprocess.run(["js-beautify", "-r", safe_path], check=True)
    
    def is_allowed_domain(self, hostname):
        for domain in self.allowed_domains:
            if hostname.endswith(domain):
                return True
        return False

    def trim_filename_to_bytes(self, filepath: str, max_bytes: int = 255) -> str:
        dir_path = os.path.dirname(filepath)
        filename = os.path.basename(filepath)
        base, ext = os.path.splitext(filename)

        total_bytes = len(filepath.encode("utf-8"))
        if total_bytes <= max_bytes:
            return filepath

        allowed_bytes = max_bytes - len(ext.encode("utf-8")) - len(dir_path.encode("utf-8")) - 1
        trimmed_base = ""
        current_bytes = 0

        for char in base:
            char_bytes = len(char.encode("utf-8"))
            if current_bytes + char_bytes > allowed_bytes:
                break
            trimmed_base += char
            current_bytes += char_bytes

        safe_filename = trimmed_base + ext
        return os.path.join(dir_path, safe_filename)

def load(l):
    l.add_option(
        name="js_tracker_domains",
        typespec=str,
        default="",
        help="e.g. fbcdn.net,facebook.com"
    )

addons = [JsTracker()]


if __name__ == "__main__":
    print("Usage: mitmproxy --scripts js_tracker.py --set js_tracker_domains=fbcdn.net,facebook.com")
    sys.exit(0)
