#!/usr/bin/env python
"""
    Screen-mirroring launcher for the physical SeedSigner HAT display.

    Not part of the app itself -- SeedSigner draws directly to the SPI-connected LCD
    via a custom display driver, not through any desktop/X11/Wayland stack, so
    ordinary screen-mirroring tools can't see it. This wraps Renderer.show_image()
    (the one place every rendered frame gets pushed to the physical display) to also
    forward each frame as a JPEG to a live MJPEG stream, so the actual 240x240 screen
    can be watched/recorded in any browser at http://<pi-ip>:8765/stream while the
    real hardware keeps working normally alongside it.

    Usage (same working directory / venv as running the app normally):
        python tools/mirror.py --loglevel INFO
    (any main.py args are passed straight through)

    Demo/dev tooling only -- not part of the production SeedSigner OS image.
"""
import io
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, "src")

MJPEG_PORT = 8765
FRAME_INTERVAL_SECS = 0.15

_latest_frame_lock = threading.Lock()
_latest_frame_jpeg: bytes = None


def _patch_renderer():
    from seedsigner.gui.renderer import Renderer

    original_show_image = Renderer.show_image

    def show_image_and_mirror(self, *args, **kwargs):
        original_show_image(self, *args, **kwargs)
        global _latest_frame_jpeg
        try:
            buf = io.BytesIO()
            self.canvas.convert("RGB").save(buf, format="JPEG", quality=85)
            with _latest_frame_lock:
                _latest_frame_jpeg = buf.getvalue()
        except Exception:
            # Never let mirroring break the real display.
            pass

    Renderer.show_image = show_image_and_mirror


class _MJPEGHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # silence default per-request access logging

    def do_GET(self):
        if self.path == "/":
            body = (
                b"<title>SeedSigner mirror</title>"
                b"<body style='margin:0;background:#111;display:flex;"
                b"align-items:center;justify-content:center;height:100vh'>"
                b"<img src='/stream' style='width:480px;height:480px;"
                b"image-rendering:pixelated'></body>"
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if self.path != "/stream":
            self.send_response(404)
            self.end_headers()
            return

        self.send_response(200)
        self.send_header("Content-Type", "multipart/x-mixed-replace; boundary=frame")
        self.end_headers()
        try:
            while True:
                with _latest_frame_lock:
                    frame = _latest_frame_jpeg
                if frame:
                    self.wfile.write(b"--frame\r\n")
                    self.wfile.write(b"Content-Type: image/jpeg\r\n")
                    self.wfile.write(f"Content-Length: {len(frame)}\r\n\r\n".encode())
                    self.wfile.write(frame)
                    self.wfile.write(b"\r\n")
                time.sleep(FRAME_INTERVAL_SECS)
        except (BrokenPipeError, ConnectionResetError):
            pass


def _start_mjpeg_server():
    server = ThreadingHTTPServer(("0.0.0.0", MJPEG_PORT), _MJPEGHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"[mirror] Open http://<this-device-ip>:{MJPEG_PORT}/ in a browser to watch/record the screen.")


if __name__ == "__main__":
    _patch_renderer()
    _start_mjpeg_server()

    import main as seedsigner_main
    seedsigner_main.main(sys.argv[1:])
