#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""用户管理模板 · 新项目初始化器

两种模式：

    full   复制整套后台（含界面），复制完就能跑
    core   只抽认证内核（userstore.py + auth.py），接进已有 Python 项目

示例：

    python scripts/init.py --target ../车间LIMS后台
    python scripts/init.py --target ../车间LIMS后台 --port 8020
    python scripts/init.py --target ../mes-api --mode core

core 模式产出在 <target>/user_auth/ 下，三个文件平级：

    userstore.py   数据层，只依赖标准库，import 即用
    auth.py        签名 Token
    selftest.py    自检脚本，先跑通再集成
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

IGNORE = shutil.ignore_patterns(
    "__pycache__", "*.pyc", ".git", ".workbuddy", "data", "*.db", "*.db-wal", "*.db-shm", ".DS_Store"
)

FULL_DIRS = ("app", "web", "tests")

RUNBAT = """@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo.
echo   {name} 启动中…
echo   浏览器打开 http://127.0.0.1:{port}
echo.
python app\\server.py --demo --port {port}
pause
"""

GITIGNORE = """data/*.db
data/*.db-wal
data/*.db-shm
data/.secret
__pycache__/
*.pyc
.venv/
venv/
"""

FULL_README = """# {name}

由「用户管理模板」生成，当前是一套可直接运行的独立后台。

## 启动

```bash
python app/server.py --demo --port {port}
# 或双击 run.bat
```

浏览器打开 http://127.0.0.1:{port}，初始账号 `admin / Aa123456`，首次登录强制改密。

## 三条使用纪律

1. **改完代码先跑自检**：`python tests/selftest.py`，全绿再提交
2. **业务代码不要碰 `app/userstore.py`**：所有账号逻辑都在里面，改动会影响审计与安全边界
3. **`data/` 不进版本库**：已由 .gitignore 挡住，备份按密码表同级别保管

## 要接进已有项目

```bash
python <模板仓库>/scripts/init.py --target . --mode core
```

然后在你自己的路由里调用 `UserStore`，见模板仓库的 README「接进自己的项目」一节。

## 目录

| 路径 | 职责 |
|---|---|
| `app/userstore.py` | 数据层：账号、密码、审计、保护规则（零依赖） |
| `app/auth.py` | 签名 Token（HMAC-SHA256，带 token_version） |
| `app/server.py` | 参考 Web 服务（标准库 http.server，可整层替换） |
| `web/` | 界面三件套，纯静态可直接部署 |
| `tests/selftest.py` | 数据层自检，不依赖 Web |
"""

CORE_README = """# user_auth

从「用户管理模板」抽出的认证内核，只依赖 Python 标准库。

## 先跑自检

```bash
python selftest.py
```

全绿说明环境没问题，再往下集成。

## 接进你的项目

```python
from userstore import UserStore, UserError
from auth import TokenSigner

db = UserStore("data/users.db", profile="standard")   # lite / standard / gxp
signer = TokenSigner(secret_path="data/.secret")      # 容器里务必显式传路径

ok, info = db.verify_login("admin", "Aa123456")
if ok:
    token = signer.sign({"uid": info["id"], "tv": db.get_token_version(info["id"])})
    payload = signer.verify(token)
```

## 三个必须注意的点

1. **鉴权中间件要校验 `tv`**：每次请求比对 `payload["tv"] == db.get_token_version(uid)`，
   否则改密码、禁用账号、强制下线都踢不掉已签发的 token。
2. **不要自己拼 SQL 查密码**：只用 `db.verify_login`，它内置失败计数与锁定。
3. **审计写入口只有一个**：`db.audit_user_change`，别绕过去直接改表。

## 接口速查

| 方法 | 用途 |
|---|---|
| `create_user(...)` | 建号，密码留空发默认密码并强制改密 |
| `update_user_fields(...)` | 改显示名/角色/有效期/启用状态（含八道保护） |
| `update_password(...)` | 改密，token_version +1 踢掉旧会话 |
| `verify_login(...)` | 登录，含失败锁定 |
| `list_users()` / `stats()` | 列表与统计（含 GxP 体检告警） |
| `list_user_audit(...)` | 审计查询 |
| `bulk_create_users(...)` | 批量导入 |
"""


def say(msg: str = ""):
    print(msg)


def fail(msg: str, code: int = 1):
    print("✗ " + msg)
    sys.exit(code)


def prepare_target(target: str, force: bool):
    target = os.path.abspath(target)
    if os.path.exists(target):
        entries = [e for e in os.listdir(target) if e not in (".git", ".DS_Store")]
        if entries and not force:
            fail("目标目录非空：%s\n  换个空目录，或加 --force 覆盖。" % target)
    os.makedirs(target, exist_ok=True)
    return target


def write(path: str, text: str):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def patch_html_title(target: str, name: str):
    """把界面标题换成新项目名，其余不动。"""
    p = os.path.join(target, "web", "index.html")
    if not os.path.exists(p):
        return
    with open(p, "r", encoding="utf-8") as f:
        html = f.read()
    html = html.replace("用户管理 · 账号中心", "%s · 账号中心" % name)
    html = html.replace('<span class="muted">用户管理模板 v1</span>', '<span class="muted">%s</span>' % name)
    with open(p, "w", encoding="utf-8", newline="\n") as f:
        f.write(html)


def copy_tree(src: str, dst: str):
    if not os.path.isdir(src):
        fail("模板文件缺失：%s\n  确认是在模板仓库根目录下执行。" % src)
    shutil.copytree(src, dst, ignore=IGNORE, dirs_exist_ok=True)


def init_full(target: str, name: str, port: int):
    for item in FULL_DIRS:
        copy_tree(os.path.join(ROOT, item), os.path.join(target, item))

    write(os.path.join(target, "run.bat"), RUNBAT.format(name=name, port=port))
    write(os.path.join(target, ".gitignore"), GITIGNORE)
    write(os.path.join(target, "README.md"), FULL_README.format(name=name, port=port))
    patch_html_title(target, name)

    # 顺手把 server.py 的默认端口改掉，避免和模板本身抢 8010
    sp = os.path.join(target, "app", "server.py")
    if os.path.exists(sp):
        with open(sp, "r", encoding="utf-8") as f:
            src = f.read()
        src = re.sub(r'default=8010', "default=%d" % port, src)
        with open(sp, "w", encoding="utf-8", newline="\n") as f:
            f.write(src)

    return [
        ("python app/server.py --demo --port %d" % port, "启动（或双击 run.bat）"),
        ("python tests/selftest.py", "跑自检，确认全绿"),
        ("http://127.0.0.1:%d" % port, "浏览器打开，admin / Aa123456"),
    ]


def init_core(target: str):
    pkg = os.path.join(target, "user_auth")
    os.makedirs(pkg, exist_ok=True)

    for src, dst in (
        (os.path.join(ROOT, "app", "userstore.py"), os.path.join(pkg, "userstore.py")),
        (os.path.join(ROOT, "app", "auth.py"), os.path.join(pkg, "auth.py")),
        (os.path.join(ROOT, "tests", "selftest.py"), os.path.join(pkg, "selftest.py")),
    ):
        if not os.path.exists(src):
            fail("模板文件缺失：%s" % src)
        shutil.copy2(src, dst)

    # selftest 原本假设自己在 <root>/tests 下，向上找 <root>/app；核心包是平级的，改成同目录
    st = os.path.join(pkg, "selftest.py")
    with open(st, "r", encoding="utf-8") as f:
        code = f.read()
    old_line = 'sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app"))'
    new_line = 'sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))'
    if old_line in code:
        code = code.replace(old_line, new_line)
        with open(st, "w", encoding="utf-8", newline="\n") as f:
            f.write(code)

    write(os.path.join(pkg, "README.md"), CORE_README)

    # 已有 .gitignore 就追加，没有就新建
    gi = os.path.join(target, ".gitignore")
    need = ["data/.secret", "data/*.db"]
    existing = ""
    if os.path.exists(gi):
        with open(gi, "r", encoding="utf-8") as f:
            existing = f.read()
    missing = [line for line in need if line not in existing]
    if missing:
        with open(gi, "a", encoding="utf-8", newline="\n") as f:
            if existing and not existing.endswith("\n"):
                f.write("\n")
            f.write("\n# 用户认证内核\n" + "\n".join(missing) + "\n")

    return [
        ("cd user_auth && python selftest.py", "先跑自检，全绿再集成"),
        ("见 user_auth/README.md", "里面有接入示例和三个必读注意事项"),
    ]


def git_init(target: str):
    if not shutil.which("git"):
        say("  （未检测到 git，跳过）")
        return
    try:
        subprocess.run(["git", "init", "-q"], cwd=target, check=True)
        subprocess.run(["git", "add", "-A"], cwd=target, check=True)
        subprocess.run(
            ["git", "-c", "user.name=template", "-c", "user.email=template@local",
             "commit", "-qm", "初始化：用户管理模板生成"],
            cwd=target, check=True,
        )
        say("  ✓ git 仓库已初始化并完成首次提交")
    except Exception as e:  # noqa: BLE001
        say("  （git 初始化跳过：%s）" % e)


def main():
    ap = argparse.ArgumentParser(
        description="用户管理模板 · 新项目初始化器",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="full = 整套后台可直接跑；core = 只要认证内核接进已有项目",
    )
    ap.add_argument("--target", required=True, help="新项目目录，不存在会自动创建")
    ap.add_argument("--mode", choices=["full", "core"], default="full", help="默认 full")
    ap.add_argument("--name", help="项目名，用于界面标题与 README，默认取目标目录名")
    ap.add_argument("--port", type=int, default=8010, help="full 模式的默认端口，默认 8010")
    ap.add_argument("--git", action="store_true", help="顺带 git init 并提交一次")
    ap.add_argument("--force", action="store_true", help="目标目录非空时也继续")
    args = ap.parse_args()

    target = prepare_target(args.target, args.force)
    name = args.name or os.path.basename(target) or "用户管理"

    say("")
    say("  用户管理模板 · 初始化")
    say("  目标  %s" % target)
    say("  模式  %s" % args.mode)
    say("")

    if args.mode == "full":
        steps = init_full(target, name, args.port)
    else:
        steps = init_core(target)

    if args.git:
        git_init(target)

    say("  已生成，下一步：")
    say("")
    for i, (cmd, desc) in enumerate(steps, 1):
        say("    %d. %-46s %s" % (i, cmd, desc))
    say("")

    if args.mode == "full":
        say("  提示：数据库首次启动时自动创建，不用手动准备。")
    else:
        say("  提示：核心包不含 Web 层，登录接口要自己写，")
        say("        鉴权中间件记得校验 tv（详见 user_auth/README.md）。")
    say("")


if __name__ == "__main__":
    main()
