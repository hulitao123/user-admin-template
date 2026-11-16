"""
用户数据层 —— 与 Web 框架无关，可直接搬进 FastAPI / Flask 项目。

包含：
  · 三张表  users / user_pwd_history / user_audit（含防篡改触发器）
  · PBKDF2-HMAC-SHA256 密码哈希（20 万次迭代，常数时间比较）
  · 三档安全策略 lite / standard / gxp（改一行 SECURITY_PROFILE 切换）
  · 登录失败锁定、账号有效期、密码历史防复用、强制轮换
  · 七道「不把自己锁死」保护
  · 结构化变更审计（old_value / new_value 快照）
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta

ITERATIONS = 200_000

# 发放给新账号的默认初始密码。所有入口（新建 / 重置 / 导入留空）都用它，
# 且只要用了默认密码，后端一律强制首登改密——默认密码人人相同，不能长期留着。
DEFAULT_INIT_PASSWORD = "Aa123456"

ROLE_LEVELS = {"viewer": 0, "operator": 1, "admin": 2}

# 出厂/通用账号名：多人共用同一个账号，审计追踪就无法归因到自然人
GENERIC_ACCOUNTS = ("admin", "administrator", "root", "sa", "sysadmin", "superadmin")

# 角色卡片文案跟前端一起走，前端不写死
ROLE_META = [
    {
        "key": "admin",
        "label": "管理员",
        "level": 2,
        "desc": "管理账号、查看审计、导入导出",
        "detail": "管账号、看审计、可导入导出",
    },
    {
        "key": "operator",
        "label": "操作员",
        "level": 1,
        "desc": "读写业务数据",
        "detail": "业务读写，不能进系统管理",
    },
    {
        "key": "viewer",
        "label": "浏览者",
        "level": 0,
        "desc": "只读查看",
        "detail": "只读查看，不能改数据",
    },
]

SECURITY_POLICIES = {
    "lite": {
        "name": "lite · 轻量",
        "min_len": 4,
        "classes": "none",
        "history": 0,
        "rotate_days": 0,
        "lock_after": 0,
        "lock_minutes": 0,
        "force_change_default": False,
        "hint": "至少 4 位，无字符要求",
    },
    "standard": {
        "name": "standard · 标准",
        "min_len": 8,
        "classes": "letter_digit",
        "history": 3,
        "rotate_days": 0,
        "lock_after": 5,
        "lock_minutes": 15,
        "force_change_default": True,
        "hint": "至少 8 位，需同时包含字母和数字",
    },
    "gxp": {
        "name": "gxp · 严格",
        "min_len": 12,
        "classes": "all4",
        "history": 5,
        "rotate_days": 90,
        "lock_after": 5,
        "lock_minutes": 30,
        "force_change_default": True,
        "hint": "至少 12 位，需包含大写、小写、数字和符号",
    },
}

def default_password(policy: dict | None = None) -> str:
    """默认初始密码，按当前策略自适应。

    lite / standard 档直接用 Aa123456；gxp 档要求 12 位且四类字符齐全，
    自动补成 Aa123456@Init，免得管理员一点「新建」就被策略挡回来。
    """
    p = policy or SECURITY_POLICIES["standard"]
    pwd = DEFAULT_INIT_PASSWORD
    if len(pwd) >= p["min_len"] and p["classes"] != "all4":
        return pwd
    if p["classes"] == "all4":
        classes = sum(
            [
                any(c.isupper() for c in pwd),
                any(c.islower() for c in pwd),
                any(c.isdigit() for c in pwd),
                any(not c.isalnum() for c in pwd),
            ]
        )
        if len(pwd) >= p["min_len"] and classes == 4:
            return pwd
        return pwd + "@Init"
    return pwd if len(pwd) >= p["min_len"] else pwd + "@Init"


USERNAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{2,32}$")
EXPIRY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}( \d{2}:\d{2}(:\d{2})?)?$")
DATETIME_FMT = "%Y-%m-%d %H:%M:%S"


class UserError(Exception):
    """业务异常，status 直接映射成 HTTP 状态码。"""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.message = message
        self.status = status


def now_str() -> str:
    """一律用本地时间。SQLite 的 CURRENT_TIMESTAMP 是 UTC，东八区会差 8 小时。"""
    return datetime.now().strftime(DATETIME_FMT)


def norm_expiry(value):
    """纯日期补 23:59:59 —— 否则『填今天到期』当场就登不上。"""
    if value is None:
        return None
    v = str(value).strip()
    if not v:
        return None
    if not EXPIRY_RE.match(v):
        raise UserError("有效期格式应为 YYYY-MM-DD")
    if len(v) == 10:
        return v + " 23:59:59"
    if len(v) == 16:
        return v + ":59"
    return v


def hash_password(password: str, salt: str | None = None, iterations: int = ITERATIONS):
    salt = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), iterations)
    return dk.hex(), salt


def verify_password(password: str, password_hash: str, salt: str) -> bool:
    if not password_hash or not salt:
        return False
    try:
        calc, _ = hash_password(password, salt)
    except Exception:
        return False
    return secrets.compare_digest(calc, password_hash)


class UserStore:
    # 改这一行就能切换档位，业务代码一行不用动
    SECURITY_PROFILE = "standard"

    def __init__(self, db_path: str, profile: str | None = None):
        self.db_path = db_path
        if profile:
            self.SECURITY_PROFILE = profile
        if self.SECURITY_PROFILE not in SECURITY_POLICIES:
            raise ValueError(f"未知的安全档位: {self.SECURITY_PROFILE}")
        parent = os.path.dirname(os.path.abspath(db_path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._init_schema()

    # ------------------------------------------------------------------ 基础
    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.db_path, timeout=15)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA journal_mode=WAL")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def policy(self) -> dict:
        p = dict(SECURITY_POLICIES[self.SECURITY_PROFILE])
        p["profile"] = self.SECURITY_PROFILE
        p["roles"] = ROLE_META
        p["default_password"] = default_password(p)
        return p

    def _init_schema(self):
        with self._conn() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id             INTEGER PRIMARY KEY AUTOINCREMENT,
                    username       TEXT NOT NULL UNIQUE,
                    password_hash  TEXT NOT NULL,
                    salt           TEXT NOT NULL,
                    role           TEXT DEFAULT 'viewer',
                    enabled        INTEGER DEFAULT 1,
                    created_at     DATETIME,
                    updated_at     DATETIME,
                    updated_by     TEXT DEFAULT '',
                    display_name   TEXT DEFAULT '',
                    last_login_at  DATETIME,
                    expires_at     DATETIME,
                    failed_count   INTEGER DEFAULT 0,
                    locked_until   DATETIME,
                    token_version  INTEGER DEFAULT 0,
                    pwd_changed_at DATETIME,
                    must_change_pwd INTEGER DEFAULT 0
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS user_pwd_history (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id       INTEGER NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt          TEXT NOT NULL,
                    created_at    DATETIME
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS user_audit (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    at        DATETIME NOT NULL,
                    actor_id  INTEGER,
                    actor     TEXT,
                    action    TEXT NOT NULL,
                    target_id INTEGER,
                    target    TEXT,
                    old_value TEXT,
                    new_value TEXT,
                    ip        TEXT,
                    result    TEXT DEFAULT 'ok',
                    note      TEXT
                )
                """
            )
            cur.execute(
                "CREATE TABLE IF NOT EXISTS sync_meta (key TEXT PRIMARY KEY, value TEXT)"
            )
            # 审计只准入不准改删 —— 不做这步，审计就只是摆设
            cur.execute(
                """
                CREATE TRIGGER IF NOT EXISTS user_audit_no_update
                BEFORE UPDATE ON user_audit
                BEGIN SELECT RAISE(ABORT, '审计记录不可修改'); END
                """
            )
            cur.execute(
                """
                CREATE TRIGGER IF NOT EXISTS user_audit_no_delete
                BEFORE DELETE ON user_audit
                BEGIN SELECT RAISE(ABORT, '审计记录不可删除'); END
                """
            )
            self._ensure_columns(cur)
        self._seed_admin()

    def _ensure_columns(self, cur):
        """老库补列，幂等可重复执行。"""
        wanted = {
            "display_name": "TEXT DEFAULT ''",
            "last_login_at": "DATETIME",
            "expires_at": "DATETIME",
            "failed_count": "INTEGER DEFAULT 0",
            "locked_until": "DATETIME",
            "token_version": "INTEGER DEFAULT 0",
            "pwd_changed_at": "DATETIME",
            "must_change_pwd": "INTEGER DEFAULT 0",
            "updated_by": "TEXT DEFAULT ''",
        }
        cur.execute("PRAGMA table_info(users)")
        have = {r["name"] for r in cur.fetchall()}
        for col, ddl in wanted.items():
            if col not in have:
                cur.execute(f"ALTER TABLE users ADD COLUMN {col} {ddl}")

    def _seed_admin(self):
        with self._conn() as conn:
            n = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
            if n:
                return
        # 初始管理员与新建账号共用同一个默认密码，全系统只有一个默认口令
        pwd = default_password(self.policy())
        with self._conn() as conn:
            h, s = hash_password(pwd)
            ts = now_str()
            conn.execute(
                """INSERT INTO users (username, password_hash, salt, role, enabled, created_at,
                       updated_at, updated_by, display_name, pwd_changed_at, must_change_pwd)
                   VALUES (?,?,?,?,1,?,?,?,?,?,?)""",
                (
                    "admin",
                    h,
                    s,
                    "admin",
                    ts,
                    ts,
                    "system",
                    "系统管理员",
                    ts,
                    1 if self.policy()["force_change_default"] else 0,
                ),
            )
        self.audit_user_change(
            action="user_create",
            actor="system",
            actor_id=None,
            target_id=1,
            target="admin",
            old=None,
            new={"username": "admin", "role": "admin", "enabled": True},
            ip="127.0.0.1",
            note="初始化默认管理员",
        )

    # ------------------------------------------------------------------ 密码策略
    def _count_classes(self, pwd: str) -> int:
        return sum(
            [
                any(c.islower() for c in pwd),
                any(c.isupper() for c in pwd),
                any(c.isdigit() for c in pwd),
                any(not c.isalnum() for c in pwd),
            ]
        )

    def validate_new_password(self, password: str, user_id: int | None = None):
        """所有建号 / 改密路径的唯一入口。返回 (ok, msg)。"""
        p = self.policy()
        password = password or ""
        if len(password) < p["min_len"]:
            return False, f"密码至少 {p['min_len']} 位"
        if len(password) > 128:
            return False, "密码不能超过 128 位"
        if p["classes"] == "letter_digit":
            if not (any(c.isalpha() for c in password) and any(c.isdigit() for c in password)):
                return False, "密码需同时包含字母和数字"
        elif p["classes"] == "all4":
            if self._count_classes(password) < 4:
                return False, "密码需包含大写、小写、数字和符号"
        if user_id and p["history"]:
            if self._is_password_reused(user_id, password, p["history"]):
                return False, f"不能重复使用最近 {p['history']} 次用过的密码"
        return True, ""

    def _is_password_reused(self, user_id: int, password: str, limit: int) -> bool:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT password_hash, salt FROM user_pwd_history WHERE user_id=? ORDER BY id DESC LIMIT ?",
                (user_id, limit),
            ).fetchall()
            for r in rows:
                if verify_password(password, r["password_hash"], r["salt"]):
                    return True
            # 当前密码也算「用过的密码」
            cur = conn.execute(
                "SELECT password_hash, salt FROM users WHERE id=?", (user_id,)
            ).fetchone()
            if cur and verify_password(password, cur["password_hash"], cur["salt"]):
                return True
        return False

    def check_password_strength(self, password: str) -> dict:
        """仅供界面展示强度条，判定仍以 validate_new_password 为准。"""
        p = self.policy()
        password = password or ""
        score = 0
        if len(password) >= max(4, p["min_len"]):
            score += 1
        if len(password) >= 12:
            score += 1
        if self._count_classes(password) >= 2:
            score += 1
        if self._count_classes(password) >= 3:
            score += 1
        labels = ["太短", "弱", "一般", "较强", "强"]
        return {"score": score, "label": labels[score]}

    # ------------------------------------------------------------------ 查询
    def _row_to_user(self, row, now: str | None = None) -> dict:
        now = now or now_str()
        enabled = bool(row["enabled"])
        expires_at = row["expires_at"]
        locked_until = row["locked_until"]
        if not enabled:
            state, state_text = "disabled", "已禁用"
        elif locked_until and locked_until > now:
            state, state_text = "locked", "锁定至 " + locked_until[5:16]
        elif expires_at and expires_at < now:
            state, state_text = "expired", "已过期"
        else:
            state, state_text = "active", "启用"
        role = row["role"]
        role_label = next((r["label"] for r in ROLE_META if r["key"] == role), role)
        return {
            "id": row["id"],
            "username": row["username"],
            "display_name": row["display_name"] or "",
            "role": role,
            "role_label": role_label,
            "enabled": enabled,
            "state": state,
            "state_text": state_text,
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "updated_by": row["updated_by"] or "",
            "last_login_at": row["last_login_at"],
            "expires_at": expires_at,
            "failed_count": row["failed_count"] or 0,
            "locked_until": locked_until,
            "must_change_pwd": bool(row["must_change_pwd"]),
            "token_version": row["token_version"] or 0,
        }

    def list_users(self) -> list[dict]:
        # 注意：SQL 里不出现 password_hash / salt
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT id, username, role, enabled, created_at, updated_at, updated_by,
                          display_name, last_login_at, expires_at, failed_count, locked_until,
                          token_version, must_change_pwd
                   FROM users ORDER BY id ASC"""
            ).fetchall()
        now = now_str()
        return [self._row_to_user(r, now) for r in rows]

    def stats(self) -> dict:
        users = self.list_users()
        counts = {k: 0 for k in ROLE_LEVELS}
        for u in users:
            counts[u["role"]] = counts.get(u["role"], 0) + 1

        # GxP 体检：这两条是审计现场最常被追问的
        generic = [
            u["username"]
            for u in users
            if u["enabled"] and u["username"].lower() in GENERIC_ACCOUNTS
        ]
        active_admins = [
            u["username"]
            for u in users
            if u["role"] == "admin" and u["enabled"] and u["state"] != "expired"
        ]
        warnings = []
        if generic:
            warnings.append(
                {
                    "code": "generic_account",
                    "level": "warn",
                    "title": "通用账号 %s 仍在启用（开发阶段可保留）" % "、".join(generic),
                    "text": "GxP 要求一人一号。开发联调时留着方便，但系统正式投入 GMP 使用前"
                            "必须禁用——否则审计追踪只显示「admin 改的」，无法归因到自然人。",
                }
            )
        if len(active_admins) < 2:
            warnings.append(
                {
                    "code": "single_admin",
                    "level": "info",
                    "title": "可用管理员只有 %d 个（正式投入前补齐）" % len(active_admins),
                    "text": "开发阶段单人够用；正式投用前建议配两个实名管理员："
                            "一是连续性（有人休假也能建号），二是权限回顾时能互相复核。",
                }
            )
        return {
            "total": len(users),
            "enabled": sum(1 for u in users if u["enabled"]),
            "locked": sum(1 for u in users if u["state"] == "locked"),
            "expired": sum(1 for u in users if u["state"] == "expired"),
            "roles": counts,
            "active_admins": active_admins,
            "warnings": warnings,
        }

    def get_user(self, user_id: int) -> dict | None:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        return self._row_to_user(row) if row else None

    def get_user_by_name(self, username: str) -> dict | None:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        return self._row_to_user(row) if row else None

    def _raw(self, user_id: int):
        with self._conn() as conn:
            return conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()

    def get_token_version(self, user_id: int) -> int:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT token_version FROM users WHERE id=?", (user_id,)
            ).fetchone()
        return (row["token_version"] or 0) if row else -1

    def verify_own_password(self, user_id: int, password: str) -> bool:
        row = self._raw(user_id)
        return bool(row and verify_password(password, row["password_hash"], row["salt"]))

    # ------------------------------------------------------------------ 保护
    def _active_admins(self, exclude_id: int | None = None) -> int:
        now = now_str()
        sql = """SELECT COUNT(*) AS c FROM users
                 WHERE role='admin' AND enabled=1
                   AND (expires_at IS NULL OR expires_at >= ?)"""
        args: list = [now]
        if exclude_id is not None:
            sql += " AND id<>?"
            args.append(exclude_id)
        with self._conn() as conn:
            return conn.execute(sql, args).fetchone()["c"]

    @staticmethod
    def _is_active_admin(role, enabled, expires_at, now: str | None = None) -> bool:
        now = now or now_str()
        return bool(role == "admin" and enabled and (not expires_at or expires_at >= now))

    # ------------------------------------------------------------------ 写入
    def create_user(
        self,
        username: str,
        password: str,
        role: str = "viewer",
        display_name: str = "",
        enabled: bool = True,
        expires_at=None,
        actor: str = "system",
        actor_id: int | None = None,
        ip: str = "",
        skip_policy: bool = False,
        must_change_pwd: bool | None = None,
    ) -> dict:
        username = (username or "").strip()
        if not USERNAME_RE.match(username):
            raise UserError("登录账号需 2~32 位，仅限字母、数字、下划线、点和短横线")
        if role not in ROLE_LEVELS:
            raise UserError("角色不合法")
        display_name = (display_name or "").strip()
        if len(display_name) > 32:
            raise UserError("显示名不能超过 32 字")
        p = self.policy()
        # 密码留空 = 用默认初始密码发放，省得管理员每次自己想一个
        if not (password or "").strip():
            password = p["default_password"]
        if not skip_policy:
            ok, msg = self.validate_new_password(password)
            if not ok:
                raise UserError(msg)
        expires = norm_expiry(expires_at)
        if must_change_pwd is None:
            must_change_pwd = 1 if p["force_change_default"] else 0
        # 用默认密码的一律强制首登改密，不受调用方传参影响
        if password == p["default_password"]:
            must_change_pwd = 1
        h, s = hash_password(password or "")
        ts = now_str()
        with self._conn() as conn:
            if conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
                raise UserError("登录账号已存在")
            cur = conn.execute(
                """INSERT INTO users (username, password_hash, salt, role, enabled, created_at,
                       updated_at, updated_by, display_name, expires_at, pwd_changed_at, must_change_pwd)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    username,
                    h,
                    s,
                    role,
                    1 if enabled else 0,
                    ts,
                    ts,
                    actor,
                    display_name,
                    expires,
                    ts,
                    1 if must_change_pwd else 0,
                ),
            )
            uid = cur.lastrowid
        self.audit_user_change(
            action="user_create",
            actor=actor,
            actor_id=actor_id,
            target_id=uid,
            target=username,
            old=None,
            new={
                "display_name": display_name,
                "role": role,
                "enabled": bool(enabled),
                "expires_at": expires or "",
            },
            ip=ip,
        )
        return self.get_user(uid)

    def update_user_fields(
        self,
        user_id: int,
        changes: dict,
        actor: str,
        actor_id: int | None = None,
        ip: str = "",
    ) -> dict:
        target = self.get_user(user_id)
        if not target:
            raise UserError("用户不存在", 404)

        fields: dict = {}
        if "display_name" in changes:
            dn = (changes.get("display_name") or "").strip()
            if len(dn) > 32:
                raise UserError("显示名不能超过 32 字")
            fields["display_name"] = dn
        if "role" in changes and changes["role"] is not None:
            if changes["role"] not in ROLE_LEVELS:
                raise UserError("角色不合法")
            fields["role"] = changes["role"]
        if "enabled" in changes and changes["enabled"] is not None:
            fields["enabled"] = bool(changes["enabled"])
        if "expires_at" in changes:
            fields["expires_at"] = norm_expiry(changes.get("expires_at"))

        # ---- 七道保护：按「操作完成后的最终状态」判断，不是看这次改了哪个字段
        final_role = fields.get("role", target["role"])
        final_enabled = fields.get("enabled", target["enabled"])
        final_expires = fields.get("expires_at", target["expires_at"])

        if not final_enabled and user_id == actor_id:
            raise UserError("不能禁用当前登录的账号，否则会把自己踢下线", 403)

        # 第 8 道（原方案没有）：改自己的角色 = 当场丢失管理权限，回不来
        if user_id == actor_id and "role" in fields and fields["role"] != target["role"]:
            raise UserError("不能修改自己的角色，请让其他管理员操作", 403)

        if self._is_active_admin(target["role"], target["enabled"], target["expires_at"]):
            if not self._is_active_admin(final_role, final_enabled, final_expires):
                if self._active_admins(exclude_id=user_id) == 0:
                    if final_role != "admin":
                        raise UserError("这是最后一个启用的管理员，不能降级", 403)
                    if not final_enabled:
                        raise UserError("这是最后一个启用的管理员，不能禁用", 403)
                    raise UserError("最后一个启用的管理员不能设成已过期的有效期", 403)

        if "password" in changes and changes["password"]:
            if user_id == actor_id:
                # 自助改密必须验旧密码（Keycloak 的 Account Console 同样要求）
                raise UserError("修改自己的密码请到「个人中心」，需要先验证当前密码", 403)
            self._set_password(user_id, changes["password"], actor, actor_id, ip, must_change=True)

        if not fields:
            return self.get_user(user_id)

        sets = ", ".join(f"{k}=?" for k in fields)
        values = list(fields.values())
        with self._conn() as conn:
            conn.execute(
                f"UPDATE users SET {sets}, updated_at=?, updated_by=? WHERE id=?",
                values + [now_str(), actor, user_id],
            )

        old_snap = {
            "display_name": target["display_name"],
            "role": target["role"],
            "enabled": target["enabled"],
            "expires_at": target["expires_at"] or "",
        }
        new_snap = {
            "display_name": fields.get("display_name", target["display_name"]),
            "role": fields.get("role", target["role"]),
            "enabled": fields.get("enabled", target["enabled"]),
            "expires_at": fields.get("expires_at", target["expires_at"]) or "",
        }
        if old_snap != new_snap:
            self.audit_user_change(
                action="user_update",
                actor=actor,
                actor_id=actor_id,
                target_id=user_id,
                target=target["username"],
                old=old_snap,
                new=new_snap,
                ip=ip,
            )
        # 禁用 / 恢复后立即让旧 token 失效
        if "enabled" in fields and bool(fields["enabled"]) != target["enabled"]:
            self.bump_token_version(user_id)
        return self.get_user(user_id)

    def _set_password(
        self,
        user_id: int,
        password: str,
        actor: str,
        actor_id: int | None,
        ip: str,
        must_change: bool,
    ):
        is_default = password == self.policy()["default_password"]
        # 默认密码是公开发放的临时口令，不受「历史 3 次不复用」约束
        ok, msg = self.validate_new_password(password, user_id=None if is_default else user_id)
        if not ok:
            raise UserError(msg)
        # 重置成默认密码时，必须让对方下次登录先改掉
        if is_default:
            must_change = True
        self.update_password(user_id, password, actor, actor_id, ip, must_change=must_change)

    def update_password(
        self,
        user_id: int,
        new_password: str,
        actor: str,
        actor_id: int | None = None,
        ip: str = "",
        must_change: bool = False,
        force: bool = False,
    ):
        """管理员重置 / 本人改密统一走这里；token_version +1 让所有会话下线。"""
        if not force:
            # 默认密码是公开发放的临时口令，不受「历史 N 次不复用」限制
            is_default = new_password == self.policy()["default_password"]
            ok, msg = self.validate_new_password(
                new_password, user_id=None if is_default else user_id
            )
            if not ok:
                raise UserError(msg)
        old = self._raw(user_id)
        if not old:
            raise UserError("用户不存在", 404)
        h, s = hash_password(new_password)
        ts = now_str()
        with self._conn() as conn:
            # 旧密码进历史表 —— 放在这里，任何改密路径都不会漏记
            conn.execute(
                "INSERT INTO user_pwd_history (user_id, password_hash, salt, created_at) VALUES (?,?,?,?)",
                (user_id, old["password_hash"], old["salt"], ts),
            )
            conn.execute(
                """UPDATE users SET password_hash=?, salt=?, pwd_changed_at=?, must_change_pwd=?,
                       updated_at=?, updated_by=?, token_version=token_version+1 WHERE id=?""",
                (h, s, ts, 1 if must_change else 0, ts, actor, user_id),
            )
        target = self.get_user(user_id)
        self.audit_user_change(
            action="user_reset_password" if must_change else "password_change",
            actor=actor,
            actor_id=actor_id,
            target_id=user_id,
            target=target["username"] if target else str(user_id),
            old={"password": "已设置"},
            new={"password": "已重置"},
            ip=ip,
            note="密码已变更，明文不记录",
        )

    def delete_user(self, user_id: int, actor: str, actor_id: int | None, ip: str = ""):
        target = self.get_user(user_id)
        if not target:
            raise UserError("用户不存在", 404)
        if user_id == actor_id:
            raise UserError("不能删除当前登录的账号", 403)
        if self._is_active_admin(target["role"], target["enabled"], target["expires_at"]):
            if self._active_admins(exclude_id=user_id) == 0:
                raise UserError("这是最后一个启用的管理员，不能删除", 403)
        with self._conn() as conn:
            conn.execute("DELETE FROM users WHERE id=?", (user_id,))
        self.audit_user_change(
            action="user_delete",
            actor=actor,
            actor_id=actor_id,
            target_id=user_id,
            target=target["username"],
            old={
                "display_name": target["display_name"],
                "role": target["role"],
                "enabled": target["enabled"],
                "expires_at": target["expires_at"] or "",
            },
            new=None,
            ip=ip,
        )

    def bump_token_version(self, user_id: int):
        with self._conn() as conn:
            conn.execute(
                "UPDATE users SET token_version=COALESCE(token_version,0)+1 WHERE id=?", (user_id,)
            )

    def unlock(self, user_id: int, actor: str, actor_id, ip=""):
        target = self.get_user(user_id)
        if not target:
            raise UserError("用户不存在", 404)
        with self._conn() as conn:
            conn.execute(
                "UPDATE users SET failed_count=0, locked_until=NULL, updated_at=?, updated_by=? WHERE id=?",
                (now_str(), actor, user_id),
            )
        self.audit_user_change(
            action="user_unlock",
            actor=actor,
            actor_id=actor_id,
            target_id=user_id,
            target=target["username"],
            old={"locked_until": target["locked_until"] or ""},
            new={"locked_until": ""},
            ip=ip,
        )

    # ------------------------------------------------------------------ 登录
    def verify_login(self, username: str, password: str, ip: str = ""):
        """返回 (ok, reason, user)。reason 已区分 禁用/锁定/过期/密码错。"""
        username = (username or "").strip()
        u = self.get_user_by_name(username)
        if not u:
            return False, "登录账号或密码错误", None
        p = self.policy()
        now = now_str()

        if u["state"] == "disabled":
            return False, "该账号已被禁用，请联系管理员", None
        if u["state"] == "locked":
            return False, f"密码错误次数过多，账号已锁定至 {u['locked_until']}", None
        if u["state"] == "expired":
            return False, "该账号已过期，请联系管理员", None

        row = self._raw(u["id"])
        if not verify_password(password, row["password_hash"], row["salt"]):
            self.record_login_failure(u["id"], ip)
            fresh = self.get_user(u["id"])
            if fresh and fresh["state"] == "locked":
                return False, f"密码错误次数过多，账号锁定 {p['lock_minutes']} 分钟", None
            left = ""
            if p["lock_after"]:
                left = f"，还可尝试 {max(0, p['lock_after'] - (fresh['failed_count'] if fresh else 0))} 次"
            return False, "登录账号或密码错误" + left, None

        self.reset_login_failure(u["id"])
        # 强制轮换：超过 rotate_days 天自动要求改密
        if p["rotate_days"] and row["pwd_changed_at"]:
            try:
                changed = datetime.strptime(row["pwd_changed_at"][:19], DATETIME_FMT)
                if (datetime.now() - changed).days >= p["rotate_days"]:
                    with self._conn() as conn:
                        conn.execute("UPDATE users SET must_change_pwd=1 WHERE id=?", (u["id"],))
                    u["must_change_pwd"] = True
            except ValueError:
                pass
        self.touch_last_login(u["id"])
        u = self.get_user(u["id"])
        return True, "", u

    def record_login_failure(self, user_id: int, ip: str = ""):
        p = self.policy()
        with self._conn() as conn:
            row = conn.execute(
                "SELECT failed_count FROM users WHERE id=?", (user_id,)
            ).fetchone()
            count = (row["failed_count"] or 0) + 1 if row else 1
            if p["lock_after"] and count >= p["lock_after"]:
                until = (datetime.now() + timedelta(minutes=p["lock_minutes"])).strftime(DATETIME_FMT)
                conn.execute(
                    "UPDATE users SET failed_count=0, locked_until=?, updated_at=? WHERE id=?",
                    (until, now_str(), user_id),
                )
            else:
                conn.execute(
                    "UPDATE users SET failed_count=?, updated_at=? WHERE id=?",
                    (count, now_str(), user_id),
                )
        if p["lock_after"] and count >= p["lock_after"]:
            u = self.get_user(user_id)
            self.audit_user_change(
                action="user_lock",
                actor="system",
                actor_id=None,
                target_id=user_id,
                target=u["username"] if u else str(user_id),
                old={"locked_until": ""},
                new={"locked_until": u["locked_until"] if u else ""},
                ip=ip,
                note=f"连续 {p['lock_after']} 次密码错误自动锁定",
            )

    def reset_login_failure(self, user_id: int):
        with self._conn() as conn:
            conn.execute(
                "UPDATE users SET failed_count=0, locked_until=NULL WHERE id=?", (user_id,)
            )

    def touch_last_login(self, user_id: int):
        with self._conn() as conn:
            conn.execute("UPDATE users SET last_login_at=? WHERE id=?", (now_str(), user_id))

    # ------------------------------------------------------------------ 审计
    def audit_user_change(
        self,
        action: str,
        actor: str,
        actor_id,
        target_id,
        target: str,
        old,
        new,
        ip: str = "",
        result: str = "ok",
        note: str = "",
    ):
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO user_audit (at, actor_id, actor, action, target_id, target,
                       old_value, new_value, ip, result, note)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    now_str(),
                    actor_id,
                    actor,
                    action,
                    target_id,
                    target,
                    json.dumps(old, ensure_ascii=False) if old is not None else None,
                    json.dumps(new, ensure_ascii=False) if new is not None else None,
                    ip,
                    result,
                    note,
                ),
            )

    @staticmethod
    def _norm_day(value, end_of_day: bool = False):
        """把纯日期补成完整时间边界。

        `at` 列存的是 "YYYY-MM-DD HH:MM:SS"。若用户只选到日（10 位），
        结束日必须补成 23:59:59，否则 `at <= '2026-11-16'` 会把当天全部漏掉。
        """
        v = (value or "").strip()
        if not v:
            return None
        if len(v) == 10 and v[4] == "-" and v[7] == "-":
            return v + (" 23:59:59" if end_of_day else " 00:00:00")
        return v

    def _audit_filter(self, target=None, action=None, start=None, end=None):
        """审计列表、计数、导出共用同一套条件，避免三处口径不一致。"""
        sql = " WHERE 1=1"
        args: list = []
        if target:
            sql += " AND (target LIKE ? OR actor LIKE ?)"
            args += [f"%{target}%", f"%{target}%"]
        if action:
            sql += " AND action=?"
            args.append(action)
        s = self._norm_day(start)
        if s:
            sql += " AND at >= ?"
            args.append(s)
        e = self._norm_day(end, end_of_day=True)
        if e:
            sql += " AND at <= ?"
            args.append(e)
        return sql, args

    def list_user_audit(
        self,
        target: str | None = None,
        action: str | None = None,
        limit: int = 200,
        offset: int = 0,
        start: str | None = None,
        end: str | None = None,
    ):
        """分页查询。limit 上限 1000 是接口保护，防止一次把审计表拉爆。"""
        limit = max(1, min(int(limit or 200), 1000))
        offset = max(0, int(offset or 0))
        where, args = self._audit_filter(target, action, start, end)
        sql = "SELECT * FROM user_audit" + where + " ORDER BY id DESC LIMIT ? OFFSET ?"
        with self._conn() as conn:
            rows = conn.execute(sql, args + [limit, offset]).fetchall()
        return self._map_audit(rows)

    def count_user_audit(self, target=None, action=None, start=None, end=None) -> int:
        where, args = self._audit_filter(target, action, start, end)
        with self._conn() as conn:
            row = conn.execute("SELECT COUNT(*) AS c FROM user_audit" + where, args).fetchone()
        return int(row["c"] or 0) if row else 0

    def export_user_audit(
        self, target=None, action=None, start=None, end=None, max_rows: int = 50000
    ):
        """导出用：不受列表 1000 条限制，但保留 5 万条上限兜底。"""
        max_rows = max(1, min(int(max_rows or 50000), 200000))
        where, args = self._audit_filter(target, action, start, end)
        sql = "SELECT * FROM user_audit" + where + " ORDER BY id ASC LIMIT ?"
        with self._conn() as conn:
            rows = conn.execute(sql, args + [max_rows]).fetchall()
        return self._map_audit(rows)


    def list_audit_for_user(self, user_id: int, limit: int = 50):
        """只返回跟这个人相关的记录：他做的、以及别人对他做的。"""
        limit = max(1, min(int(limit or 50), 200))
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM user_audit
                   WHERE actor_id=? OR target_id=?
                   ORDER BY id DESC LIMIT ?""",
                (user_id, user_id, limit),
            ).fetchall()
        return self._map_audit(rows)

    @staticmethod
    def _map_audit(rows):
        out = []
        for r in rows:
            try:
                old = json.loads(r["old_value"]) if r["old_value"] else None
            except json.JSONDecodeError:
                old = None
            try:
                new = json.loads(r["new_value"]) if r["new_value"] else None
            except json.JSONDecodeError:
                new = None
            out.append(
                {
                    "id": r["id"],
                    "at": r["at"],
                    "actor": r["actor"],
                    "action": r["action"],
                    "target": r["target"],
                    "old": old,
                    "new": new,
                    "ip": r["ip"],
                    "result": r["result"],
                    "note": r["note"],
                }
            )
        return out

    # ------------------------------------------------------------------ 批量导入
    def bulk_create_users(self, rows: list[dict], actor: str, actor_id=None, ip: str = ""):
        created, failed = [], []
        for idx, row in enumerate(rows or []):
            try:
                u = self.create_user(
                    username=row.get("username", ""),
                    password=row.get("password", ""),
                    role=row.get("role") or "viewer",
                    display_name=row.get("display_name", ""),
                    expires_at=row.get("expires_at") or None,
                    actor=actor,
                    actor_id=actor_id,
                    ip=ip,
                    must_change_pwd=1,
                )
                created.append({"username": u["username"], "id": u["id"]})
            except UserError as e:
                failed.append({"row": idx + 1, "username": row.get("username", ""), "error": e.message})
        if created:
            self.audit_user_change(
                action="user_import",
                actor=actor,
                actor_id=actor_id,
                target_id=None,
                target=f"{len(created)} 个账号",
                old=None,
                new={"created": [c["username"] for c in created]},
                ip=ip,
                note=f"批量导入成功 {len(created)} 条，失败 {len(failed)} 条",
            )
        return {"created": created, "failed": failed}
