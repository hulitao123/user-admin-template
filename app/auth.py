"""无依赖的签名 Token（HMAC-SHA256）。

只做三件事：签发、校验、读 payload。真实项目要换成 JWT 库也行，
但要保证 payload 里带 tv（token_version），否则踢不掉任何会话。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _b64d(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


class TokenSigner:
    """secret_path 不传时落在模块同级 ../data/.secret。

    把本文件搬进别的项目后，建议显式传 secret_path，
    否则密钥会跟着代码目录跑，容器化部署时每次重建都会换密钥。
    """

    def __init__(self, secret: str | None = None, ttl_hours: int = 12, secret_path: str | None = None):
        self.secret = (secret or self._load_secret(secret_path)).encode()
        self.ttl = int(ttl_hours * 3600)

    @staticmethod
    def default_secret_path() -> str:
        here = os.path.dirname(os.path.abspath(__file__))
        return os.path.abspath(os.path.join(here, "..", "data", ".secret"))

    @classmethod
    def _load_secret(cls, path: str | None = None) -> str:
        """密钥持久化到 .secret，重启后已签发的 token 仍然有效。"""
        path = path or cls.default_secret_path()
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                s = f.read().strip()
                if s:
                    return s
        os.makedirs(os.path.dirname(path), exist_ok=True)
        s = secrets.token_hex(32)
        with open(path, "w", encoding="utf-8") as f:
            f.write(s)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return s

    def _sig(self, body: str) -> str:
        return _b64e(hmac.new(self.secret, body.encode(), hashlib.sha256).digest())

    def sign(self, payload: dict) -> str:
        data = dict(payload)
        data.setdefault("iat", int(time.time()))
        data["exp"] = data.get("exp") or int(time.time()) + self.ttl
        body = _b64e(json.dumps(data, separators=(",", ":")).encode())
        return body + "." + self._sig(body)

    def verify(self, token: str) -> dict | None:
        if not token or "." not in token:
            return None
        body, sig = token.rsplit(".", 1)
        if not hmac.compare_digest(self._sig(body), sig):
            return None
        try:
            data = json.loads(_b64d(body))
        except Exception:
            return None
        if data.get("exp", 0) < int(time.time()):
            return None
        return data
