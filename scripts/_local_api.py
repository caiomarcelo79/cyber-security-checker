"""Transporte da API usado pelas ferramentas locais de laboratório."""

import argparse
from urllib.parse import urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    OpenerDirector,
    ProxyHandler,
    build_opener,
)


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def api_base_url(value: str) -> str:
    try:
        url = urlsplit(value)
        port = url.port
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Informe uma URL de API válida.") from exc
    if (
        not url.hostname
        or url.username is not None
        or url.password is not None
        or url.path.rstrip("/")
        or url.query
        or url.fragment
        or port == 0
        or (
            url.scheme != "https"
            and (url.scheme != "http" or url.hostname not in {"127.0.0.1", "::1"})
        )
    ):
        raise argparse.ArgumentTypeError("Use a origem HTTPS da API ou HTTP em IP de loopback.")
    return value.rstrip("/")


def local_api_opener() -> OpenerDirector:
    return build_opener(ProxyHandler({}), NoRedirects())
