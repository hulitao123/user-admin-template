"""零依赖 Web 服务：标准库 http.server + SQLite。

启动：
    python app/server.py                 # 默认 8010 端口
    python app/server.py --port 8080
    python app/server.py --demo          # 附带演示账号
    python app/server.py --reset         # 清库重来（含演示数据）
"""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import sys
import traceback
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from auth import TokenSigner  # noqa: E402
from userstore import ROLE_LEVELS, UserError, UserStore  # noqa: E402

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEB_DIR = os.path.join(BASE_DIR, "web")
DATA_DIR = os.path.join(BASE_DIR, "data")


# --------------------------------------------------------------------- 路由表
# 静态路径必须排在 <id> 之前，否则 "audit" 会被当成 id
ROUTES = [
    ("POST", r"^/api/login$", "login", None),
    ("GET", r"^/api/me$", "me", "any"),
    ("PUT", r"^/api/me$", "update_me", "any"),
    ("GET", r"^/api/me/audit$", "my_audit", "any"),
    ("POST", r"^/api/logout$", "logout", "any"),
    ("POST", r"^/api/password$", "change_password", "any"),
    ("GET", r"^/api/users$", "list_users", "admin"),
    ("POST", r"^/api/users$", "create_user", "admin"),
    ("GET", r"^/api/users/audit$", "audit", "admin"),
    ("GET", r"^/api/users/export$", "export_csv", "admin"),
    ("POST", r"^/api/users/import$", "import_users", "admin"),
    ("PUT", r"^/api/users/(\d+)$", "update_user", "admin"),
    ("DELETE", r"^/api/users/(\d+)$", "delete_user", "admin"),
    ("POST", r"^/api/users/(\d+)/unlock$", "unlock_user", "admin"),
    ("POST", r"^/api/users/(\d+)/kick$", "kick_user", "admin"),
]

PUBLIC_PATHS = {"/api/login"}

CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".ico": "image/x-icon",
    ".json": "application/json; charset=utf-8",
}


def csv_cell(v) -> str:
    s = "" if v is None else str(v)
    if any(c in s for c in [",", '"', "\n", "\r"]):
        s = '"' + s.replace('"', '""') + '"'
    return s


class Api:
    def __init__(self, db: UserStore, signer: TokenSigner):
        self.db = db
        self.signer = signer

    # ---------------------------------------------------------------- 登录
    def login(self, body, headers, ip):
        username = (body.get("username") or "").strip()
        password = body.get("password") or ""
        ok, reason, user = self.db.verify_login(username, password, ip=ip)
        if not ok:
            return 401, {"ok": False, "error": reason}
        token = self.signer.sign(
            {
                "user_id": user["id"],
                "username": user["username"],
                "role": user["role"],
                "tv": user["token_version"],
            }
        )
        return 200, {
            "ok": True,
            "token": token,
            "user": self._public_user(user),
            "policy": self.db.policy(),
            "must_change_pwd": user["must_change_pwd"],
        }

    @staticmethod
    def _public_user(u: dict) -> dict:
        keys = [
            "id", "username", "display_name", "role", "role_label", "state", "state_text",
            "last_login_at", "expires_at", "created_at", "must_change_pwd",
        ]
        return {k: u.get(k) for k in keys}

    def logout(self, body, headers, ip, ctx):
        return 200, {"ok": True}

    def me(self, body, headers, ip, ctx):
        return 200, {"ok": True, "user": self._public_user(ctx["user"]), "policy": self.db.policy()}

    def update_me(self, body, headers, ip, ctx):
        """个人中心：只能改自己的显示名。改密码走 /api/password（必须验旧密码）。"""
        changes = {}
        if "display_name" in body:
            changes["display_name"] = body.get("display_name")
        if not changes:
            raise UserError("没有可修改的内容")
        uid = ctx["user"]["id"]
        u = self.db.update_user_fields(uid, changes, ctx["user"]["username"], uid, ip)
        return 200, {"ok": True, "user": self._public_user(u), "policy": self.db.policy()}

    def my_audit(self, body, headers, ip, ctx, query):
        rows = self.db.list_audit_for_user(
            ctx["user"]["id"], (query.get("limit") or ["50"])[0]
        )
        return 200, {"ok": True, "audit": rows}

    # ---------------------------------------------------------------- 用户
    def list_users(self, body, headers, ip, ctx):
        return 200, {
            "ok": True,
            "users": self.db.list_users(),
            "stats": self.db.stats(),
            "policy": self.db.policy(),
            "me": self._public_user(ctx["user"]),
        }

    def create_user(self, body, headers, ip, ctx):
        u = self.db.create_user(
            username=body.get("username"),
            password=body.get("password"),
            role=body.get("role") or "viewer",
            display_name=body.get("display_name") or "",
            enabled=bool(body.get("enabled", True)),
            expires_at=body.get("expires_at"),
            actor=ctx["user"]["username"],
            actor_id=ctx["user"]["id"],
            ip=ip,
            must_change_pwd=body.get("must_change_pwd"),
        )
        return 200, {"ok": True, "user": u}

    def update_user(self, body, headers, ip, ctx, user_id):
        u = self.db.update_user_fields(
            user_id,
            body,
            actor=ctx["user"]["username"],
            actor_id=ctx["user"]["id"],
            ip=ip,
        )
        return 200, {"ok": True, "user": u, "policy": self.db.policy()}

    def delete_user(self, body, headers, ip, ctx, user_id):
        self.db.delete_user(user_id, ctx["user"]["username"], ctx["user"]["id"], ip)
        return 200, {"ok": True}

    def unlock_user(self, body, headers, ip, ctx, user_id):
        self.db.unlock(user_id, ctx["user"]["username"], ctx["user"]["id"], ip)
        return 200, {"ok": True}

    def kick_user(self, body, headers, ip, ctx, user_id):
        if user_id == ctx["user"]["id"]:
            raise UserError("要下线自己请直接退出登录", 400)
        target = self.db.get_user(user_id)
        if not target:
            raise UserError("用户不存在", 404)
        self.db.bump_token_version(user_id)
        self.db.audit_user_change(
            action="user_kick",
            actor=ctx["user"]["username"],
            actor_id=ctx["user"]["id"],
            target_id=user_id,
            target=target["username"],
            old={"online": True},
            new={"online": False},
            ip=ip,
            note="强制下线",
        )
        return 200, {"ok": True}

    def change_password(self, body, headers, ip, ctx):
        uid = ctx["user"]["id"]
        old_pwd = body.get("old_password") or ""
        new_pwd = body.get("new_password") or ""
        if not self.db.verify_own_password(uid, old_pwd):
            raise UserError("当前密码不正确")
        self.db._set_password(uid, new_pwd, ctx["user"]["username"], uid, ip, must_change=False)
        user = self.db.get_user(uid)
        token = self.signer.sign(
            {
                "user_id": user["id"],
                "username": user["username"],
                "role": user["role"],
                "tv": user["token_version"],
            }
        )
        return 200, {"ok": True, "token": token, "user": self._public_user(user)}

    # ---------------------------------------------------------------- 审计 / 导出 / 导入
    def audit(self, body, headers, ip, ctx, query):
        rows = self.db.list_user_audit(
            target=(query.get("target") or [""])[0],
            action=(query.get("action") or [""])[0],
            limit=(query.get("limit") or ["200"])[0],
        )
        return 200, {"ok": True, "audit": rows}

    def export_csv(self, body, headers, ip, ctx):
        rows = self.db.list_users()
        buf = io.StringIO()
        buf.write("\ufeff")  # Excel 打开中文不乱码
        buf.write("ID,登录账号,显示名,角色,状态,最后登录,有效期,创建时间\n")
        for u in rows:
            buf.write(
                ",".join(
                    csv_cell(v)
                    for v in [
                        u["id"],
                        u["username"],
                        u["display_name"],
                        u["role_label"],
                        u["state_text"],
                        u["last_login_at"] or "",
                        u["expires_at"] or "",
                        u["created_at"] or "",
                    ]
                )
                + "\n"
            )
        self.db.audit_user_change(
            action="user_export",
            actor=ctx["user"]["username"],
            actor_id=ctx["user"]["id"],
            target_id=None,
            target=f"{len(rows)} 个账号",
            old=None,
            new={"exported": len(rows)},
            ip=ip,
            note="导出账号清单 CSV（不含密码）",
        )
        name = "users_" + datetime.now().strftime("%Y%m%d_%H%M") + ".csv"
        return 200, buf.getvalue().encode("utf-8"), (
            "text/csv; charset=utf-8",
            f'attachment; filename="{name}"',
        )

    def import_users(self, body, headers, ip, ctx):
        rows = body.get("rows") or []
        if not isinstance(rows, list):
            raise UserError("rows 必须是数组")
        if len(rows) > 500:
            raise UserError("单次最多导入 500 条")
        result = self.db.bulk_create_users(
            rows, ctx["user"]["username"], ctx["user"]["id"], ip
        )
        return 200, {"ok": True, **result}


class Handler(BaseHTTPRequestHandler):
    server_version = "UserAdmin/1.0"
    api: Api
    db: UserStore

    # ---------------------------------------------------------------- 基础
    def log_message(self, fmt, *args):
        sys.stderr.write("[%s] %s\n" % (datetime.now().strftime("%H:%M:%S"), fmt % args))

    def _send(self, status: int, payload=None, content_type="application/json; charset=utf-8", extra=None):
        if isinstance(payload, (dict, list)):
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        elif isinstance(payload, bytes):
            data = payload
        else:
            data = ("" if payload is None else str(payload)).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _client_ip(self) -> str:
        fwd = self.headers.get("X-Forwarded-For") or ""
        if fwd:
            return fwd.split(",")[0].strip()
        return self.client_address[0] if self.client_address else ""

    def _read_json(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if not length:
            return {}
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
        except Exception:
            raise UserError("请求体不是合法 JSON")
        return data if isinstance(data, dict) else {}

    # ---------------------------------------------------------------- 鉴权
    def _auth(self, required):
        if required is None:
            return None
        header = self.headers.get("Authorization") or ""
        if not header.startswith("Bearer "):
            raise UserError("未登录或登录已失效", 401)
        payload = self.api.signer.verify(header[7:].strip())
        if not payload:
            raise UserError("登录已失效，请重新登录", 401)
        uid = payload.get("user_id")
        if self.db.get_token_version(uid) != payload.get("tv", 0):
            raise UserError("登录已失效，请重新登录", 401)
        user = self.db.get_user(uid)
        if not user:
            raise UserError("账号不存在", 401)
        if user["state"] == "disabled":
            raise UserError("该账号已被禁用", 401)
        if user["state"] == "expired":
            raise UserError("该账号已过期", 401)
        if user["must_change_pwd"] and self.path.split("?")[0] not in (
            "/api/me",
            "/api/password",
            "/api/logout",
        ):
            raise UserError("请先修改初始密码", 403)
        if required != "any":
            need = ROLE_LEVELS.get(required, 99)
            have = ROLE_LEVELS.get(user["role"], -1)
            if have < need:
                raise UserError("没有权限执行该操作", 403)
        return {"user": user, "payload": payload}

    # ---------------------------------------------------------------- 分发
    def _dispatch(self, method: str):
        parsed = urlparse(self.path)
        path = unquote(parsed.path)
        if not path.startswith("/api/"):
            if method in ("GET", "HEAD"):
                return self._serve_static(path)
            return self._send(405, {"ok": False, "error": "方法不支持"})

        body = self._read_json() if method in ("POST", "PUT", "PATCH", "DELETE") else {}
        query = parse_qs(parsed.query)
        ip = self._client_ip()

        for m, pattern, handler_name, required in ROUTES:
            if m != method:
                continue
            match = re.match(pattern, path)
            if not match:
                continue
            try:
                ctx = self._auth(required)
                fn = getattr(self.api, handler_name)
                args = []
                if handler_name in ("update_user", "delete_user", "unlock_user", "kick_user"):
                    args = [int(match.group(1))]
                elif handler_name in ("audit", "my_audit"):
                    args = [query]
                if required is None:
                    result = fn(body, self.headers, ip)
                else:
                    result = fn(body, self.headers, ip, ctx, *args)
                return self._send(*result)
            except UserError as e:
                return self._send(e.status, {"ok": False, "error": e.message})
        return self._send(404, {"ok": False, "error": "接口不存在"})

    def _serve_static(self, path: str):
        rel = "index.html" if path in ("/", "") else path.lstrip("/")
        full = os.path.realpath(os.path.join(WEB_DIR, rel))
        if not full.startswith(os.path.realpath(WEB_DIR)):
            return self._send(403, {"ok": False, "error": "禁止访问"})
        if not os.path.isfile(full):
            return self._send(404, "404 Not Found", "text/plain; charset=utf-8")
        ext = os.path.splitext(full)[1].lower()
        with open(full, "rb") as f:
            data = f.read()
        return self._send(200, data, CONTENT_TYPES.get(ext, "application/octet-stream"))

    def do_GET(self):
        try:
            self._dispatch("GET")
        except Exception:
            traceback.print_exc()
            self._send(500, {"ok": False, "error": "服务器内部错误"})

    def do_HEAD(self):
        self.do_GET()

    def do_POST(self):
        try:
            self._dispatch("POST")
        except Exception:
            traceback.print_exc()
            self._send(500, {"ok": False, "error": "服务器内部错误"})

    def do_PUT(self):
        try:
            self._dispatch("PUT")
        except Exception:
            traceback.print_exc()
            self._send(500, {"ok": False, "error": "服务器内部错误"})

    def do_DELETE(self):
        try:
            self._dispatch("DELETE")
        except Exception:
            traceback.print_exc()
            self._send(500, {"ok": False, "error": "服务器内部错误"})


def seed_demo(db: UserStore):
    """演示数据：覆盖 锁定 / 已过期 / 已禁用 / 从未登录 四种状态。"""
    if db.stats()["total"] > 1:
        return
    from datetime import timedelta

    def day(offset):
        return (datetime.now() + timedelta(days=offset)).strftime("%Y-%m-%d")

    demo = [
        ("zhangsan", "Zhangsan2026", "admin", "张三（灌装车间）", True, None),
        ("sunqi", "Sunqi2026x", "operator", "孙七", True, day(-1)),
        ("lisi", "Lisi2026aa", "operator", "李四（外包）", True, day(30)),
        ("wangwu", "Wangwu2026a", "viewer", "王五（外包）", True, day(20)),
        ("zhaoliu", "Zhaoliu2026", "viewer", "赵六", True, day(-5)),
        ("qianba", "Qianba2026", "viewer", "钱八", False, None),
    ]
    for username, pwd, role, dn, enabled, exp in demo:
        try:
            db.create_user(
                username=username,
                password=pwd,
                role=role,
                display_name=dn,
                enabled=enabled,
                expires_at=exp,
                actor="system",
                ip="127.0.0.1",
                # 演示账号用的是自定义强密码，不是默认初始密码，不强制改密
                must_change_pwd=0,
            )
        except UserError as e:
            print("  [demo] %s 跳过：%s" % (username, e.message))
    # 让孙七处于「锁定」状态
    u = db.get_user_by_name("sunqi")
    if u:
        for _ in range(5):
            db.record_login_failure(u["id"])


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

    ap = argparse.ArgumentParser(description="用户管理模板")
    ap.add_argument("--port", type=int, default=8010)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--profile", choices=["lite", "standard", "gxp"], default=None,
                    help="安全档位，默认 standard")
    ap.add_argument("--demo", action="store_true", help="写入演示账号")
    ap.add_argument("--reset", action="store_true", help="删除现有数据库后重建")
    ap.add_argument("--db", default=os.path.join(DATA_DIR, "users.db"))
    args = ap.parse_args()

    os.makedirs(DATA_DIR, exist_ok=True)
    fresh = not os.path.exists(args.db)
    if args.reset and os.path.exists(args.db):
        for suffix in ("", "-wal", "-shm"):
            p = args.db + suffix
            if os.path.exists(p):
                os.remove(p)
        print("已清空数据库：%s" % args.db)
        fresh = True

    db = UserStore(args.db, profile=args.profile)
    if args.demo:
        seed_demo(db)

    signer = TokenSigner()
    api = Api(db, signer)
    Handler.api = api
    Handler.db = db

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    p = db.policy()
    print("=" * 62)
    print("  用户管理模板  ·  安全档位 %s" % p["profile"])
    print("  地址     http://%s:%d" % (args.host, args.port))
    if fresh:
        tip = "首次登录会要求改密" if p["force_change_default"] else "轻量档，不强制改密"
        print("  账号     admin / %s   （%s）" % (p["default_password"], tip))
    else:
        print("  账号     沿用已有数据库，账号密码不变")
    print("  数据库   %s" % os.path.abspath(args.db))
    print("  记住     %s" % p["hint"])
    print("=" * 62)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止。")
        httpd.server_close()


if __name__ == "__main__":
    main()
