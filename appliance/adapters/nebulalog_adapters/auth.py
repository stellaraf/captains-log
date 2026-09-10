"""Real fresh-session Keycloak password + TOTP + PKCE health check.

No password grant, browser-authentication bypass, TLS bypass or credential logging.
The resulting token is accepted only after the application validates it at /api/me.
"""
import base64
import hashlib
import hmac
from html.parser import HTMLParser
from http.cookiejar import CookieJar
from http.client import HTTPSConnection
import json
import secrets
import socket
import ssl
import struct
import time
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit
from urllib.request import build_opener, HTTPCookieProcessor, HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request
from nebulalog_manager.common import Refused


def origin(url):
    p = urlsplit(url)
    return p.scheme, p.hostname, p.port or (443 if p.scheme == "https" else 80)


def tls_context(config):
    return ssl.create_default_context(cafile=config.get("ca_file"))


class LocalHTTPSHandler(HTTPSHandler):
    """Use the trusted local edge, preserving its real Host, SNI and CA checks."""
    def https_open(self, request):
        context = self._context
        class LocalConnection(HTTPSConnection):
            def connect(self):
                plain = socket.create_connection(("127.0.0.1", self.port), self.timeout)
                try:
                    self.sock = self._context.wrap_socket(plain, server_hostname=self.host)
                except BaseException:
                    plain.close()
                    raise
        return self.do_open(LocalConnection, request, context=context)


def totp(secret, algorithm="SHA256", digits=6, period=30, now=None):
    if algorithm not in ("SHA256", "SHA512") or digits not in (6, 8) or period != 30:
        raise Refused("Health OTP must match the qualified SHA256/SHA512 30-second realm policy")
    try:
        key = base64.b32decode(secret.upper() + "=" * ((8 - len(secret) % 8) % 8))
    except (ValueError, TypeError) as exc:
        raise Refused("Invalid health OTP key") from exc
    if len(key) < 16:
        raise Refused("Health OTP key is too short")
    counter = int(time.time() if now is None else now) // period
    digest = hmac.new(key, struct.pack(">Q", counter), getattr(hashlib, algorithm.lower())).digest()
    offset = digest[-1] & 15
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7fffffff
    return str(value % (10 ** digits)).zfill(digits)


class Form(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self.current = None

    def handle_starttag(self, tag, attrs):
        data = dict(attrs)
        if tag == "form":
            self.current = {"action": data.get("action", ""), "fields": {}, "names": set()}
        elif tag == "input" and self.current is not None and data.get("name"):
            self.current["names"].add(data["name"])
            if data.get("type") == "hidden":
                self.current["fields"][data["name"]] = data.get("value", "")

    def handle_endtag(self, tag):
        if tag == "form" and self.current is not None:
            self.forms.append(self.current)
            self.current = None


class Callback(Exception):
    def __init__(self, url):
        self.url = url


class RestrictedRedirect(HTTPRedirectHandler):
    def __init__(self, issuer, redirect_uri):
        self.issuer = issuer
        self.redirect_uri = redirect_uri

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urlsplit(newurl)
        callback = urlsplit(self.redirect_uri)
        if origin(newurl) == origin(self.redirect_uri) and target.path == callback.path:
            raise Callback(newurl)
        if origin(newurl) != origin(self.issuer):
            raise Refused("Local health sign-in attempted an external redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def response_bytes(response):
    body = response.read(1024 * 1024 + 1)
    if len(body) > 1024 * 1024:
        raise Refused("Oversized identity health response")
    return body


def local_auth(config, *, opener_factory=build_opener):
    probe = config["auth_probe"]
    issuer = config["issuer"].rstrip("/")
    redirect = probe["redirect_uri"]
    if origin(issuer)[0] != "https" or origin(redirect)[0] != "https":
        raise Refused("Appliance identity health requires HTTPS with certificate validation")
    opener = opener_factory(ProxyHandler({}), LocalHTTPSHandler(context=tls_context(config)), HTTPCookieProcessor(CookieJar()),
                            RestrictedRedirect(issuer, redirect))
    verifier = secrets.token_urlsafe(48)
    state = secrets.token_urlsafe(32)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    params = {"client_id": probe["client_id"], "redirect_uri": redirect, "response_type": "code",
              "scope": "openid", "state": state, "nonce": secrets.token_urlsafe(32),
              "code_challenge": challenge, "code_challenge_method": "S256", "prompt": "login", "kc_idp_hint": ""}
    request = Request(issuer + "/protocol/openid-connect/auth?" + urlencode(params))
    completed = set()
    code = None
    try:
        for _ in range(5):
            try:
                response = opener.open(request, timeout=15)
            except Callback as callback:
                values = parse_qs(urlsplit(callback.url).query)
                if values.get("state") != [state] or len(values.get("code", [])) != 1:
                    raise Refused("Identity callback state/code did not match")
                code = values["code"][0]
                break
            parser = Form()
            parser.feed(response_bytes(response).decode("utf-8"))
            forms = [form for form in parser.forms if "password" in form["names"] or "otp" in form["names"]]
            if len(forms) != 1:
                raise Refused("Local health sign-in requires an unexpected interaction")
            form = forms[0]
            target = urljoin(response.url, form["action"])
            if origin(target) != origin(issuer):
                raise Refused("Identity form action left the trusted issuer origin")
            values = form["fields"]
            if "password" in form["names"]:
                if "password" in completed:
                    raise Refused("Local health password was rejected")
                values.update(username=probe["username"], password=probe["password"])
                completed.add("password")
            if "otp" in form["names"]:
                if "otp" in completed:
                    raise Refused("Local health OTP was rejected")
                values["otp"] = totp(probe["totp_secret"], probe.get("totp_algorithm", "SHA256"),
                                     probe.get("totp_digits", 6), probe.get("totp_period", 30))
                completed.add("otp")
            request = Request(target, data=urlencode(values).encode(), method="POST")
        if not code or completed != {"password", "otp"}:
            raise Refused("Fresh local password and OTP steps were not both completed")
        values = {"grant_type": "authorization_code", "code": code, "redirect_uri": redirect,
                  "client_id": probe["client_id"], "code_verifier": verifier}
        token_response = opener.open(Request(issuer + "/protocol/openid-connect/token",
                                            data=urlencode(values).encode()), timeout=15)
        token = json.loads(response_bytes(token_response))["access_token"]
        headers = {"Authorization": "Bearer " + token}
        identity = json.loads(response_bytes(opener.open(Request(config["api_url"].rstrip("/") + "/api/me",
                                                                  headers=headers), timeout=15)))
        if identity.get("role") != "VIEWER":
            raise Refused("Health identity must resolve to the application VIEWER role")
        return token, {"password": True, "otp": True, "pkce": True, "api_role": "VIEWER"}
    except (HTTPError, KeyError, ValueError, OSError) as exc:
        # No response body, URL containing codes, password, OTP seed or token is returned.
        raise Refused("Local password/OTP identity health failed") from exc
