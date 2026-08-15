import csv
import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class DemoHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            body = b"""<!doctype html><html><body>
            <a href="/page?item=1">page</a>
            <form><input name="username"><input type="hidden" name="csrf"></form>
            <!-- api_key: demo-value -->
            <p>Release 3.2.1 on 10.0.0.5</p>
            </body></html>"""
            status = 200
        elif self.path == "/page?item=1":
            body = b"<html><body><textarea name='message'></textarea></body></html>"
            status = 200
        else:
            body = b"<html><body>missing</body></html>"
            status = 404

        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


def test_cli_crawls_local_site_and_writes_csv_and_json(tmp_path):
    server = ThreadingHTTPServer(("127.0.0.1", 0), DemoHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    project_root = Path(__file__).resolve().parents[1]
    csv_path = tmp_path / "results.csv"
    json_path = tmp_path / "results.json"
    target = f"http://127.0.0.1:{server.server_port}/"

    try:
        result = subprocess.run(
            [
                sys.executable,
                str(project_root / "paracrawler.py"),
                "-u",
                target,
                "--delay",
                "0",
                "--timeout",
                "2",
                "-m",
                "2",
                "-o",
                str(csv_path),
                "-j",
                str(json_path),
            ],
            cwd=project_root,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    finally:
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=2)

    assert result.returncode == 0, result.stderr
    assert "Result color legend:" in result.stdout
    assert "Total URLs crawled: 2 URLs." in result.stdout, result.stdout

    with csv_path.open(encoding="utf-8-sig", newline="") as csv_file:
        rows = list(csv.DictReader(csv_file))
    assert {row["URL"] for row in rows} == {
        target,
        f"{target}page?item=1",
    }

    data = json.loads(json_path.read_text(encoding="utf-8-sig"))
    assert data["total_urls_crawled"] == 2
    assert len(data["endpoints"]) == 2
    assert data["endpoints"][0]["versions"] == ["3.2.1"]
    assert "10.0.0.5" in data["endpoints"][0]["ips"]
