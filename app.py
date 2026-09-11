from __future__ import annotations

import os
from socketserver import ThreadingMixIn
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

from help_api_finder.wsgi import create_application


application = create_application()


class ThreadingWSGIServer(ThreadingMixIn, WSGIServer):
    daemon_threads = True


def main() -> None:
    try:
        port = int(os.environ.get("PORT", os.environ.get("FINDER_PORT", "8765")))
    except ValueError:
        raise SystemExit("FINDER_PORT must be a number.") from None
    if not 1024 <= port <= 65535:
        raise SystemExit("FINDER_PORT must be between 1024 and 65535.")
    host = os.environ.get("FINDER_HOST", "127.0.0.1")
    server = make_server(
        host,
        port,
        application,
        server_class=ThreadingWSGIServer,
        handler_class=WSGIRequestHandler,
    )
    print(f"Keylight development server: http://{host}:{port}")
    print("Production에서는 Docker Compose의 Gunicorn/Caddy 구성을 사용하세요.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
