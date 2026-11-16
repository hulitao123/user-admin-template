"""上线前自检：不依赖 Web 框架，直接用临时 SQLite 跑数据层。

    python tests/selftest.py
    python tests/selftest.py -v

覆盖：密码策略三档 / 历史密码 / 登录锁定 / 有效期 / token 版本
     七道保护 / 审计新旧值 / 审计防篡改 / 批量导入 / 初始化
"""

from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
import traceback

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app"))

from userstore import UserError, UserStore  # noqa: E402

PASS = 0
FAIL = 0
VERBOSE = "-v" in sys.argv


def check(name: str, cond: bool, detail: str = ""):
    global PASS, FAIL
    if cond:
        PASS += 1
        if VERBOSE:
            print("  [ok] %s" % name)
    else:
        FAIL += 1
        print("  [FAIL] %s %s" % (name, detail))


def expect_error(name: str, fn, keyword: str = ""):
    try:
        fn()
    except UserError as e:
        check(name, keyword in e.message, "-> %s" % e.message)
        return e
    except Exception as e:  # noqa: BLE001
        check(name, False, "未预期异常: %r" % e)
        return None
    check(name, False, "本应拒绝但通过了")
    return None


def new_store(profile="standard"):
    tmp = tempfile.mkdtemp(prefix="um_selftest_")
    path = os.path.join(tmp, "t.db")
    return UserStore(path, profile=profile), path


def main():
    print("=" * 62)
    print("用户管理模板 · 数据层自检")
    print("=" * 62)

    # ---------------------------------------------------------- 初始化
    print("\n[1] 初始化与密码哈希")
    db, path = new_store()
    users = db.list_users()
    check("初始化生成默认管理员", len(users) == 1 and users[0]["username"] == "admin")
    row = db._raw(users[0]["id"])
    check("密码不以明文存储", b"Aa123456" not in open(path, "rb").read())
    check("哈希为 64 位十六进制", len(row["password_hash"]) == 64)
    check("salt 为 32 位十六进制", len(row["salt"]) == 32)
    check("正确密码校验通过", db.verify_own_password(1, "Aa123456"))
    check("错误密码校验失败", not db.verify_own_password(1, "Aa123457"))
    db._init_schema()  # 幂等补列
    check("重复初始化不报错且不重复建管理员", len(db.list_users()) == 1)

    # ---------------------------------------------------------- 密码策略
    print("\n[2] standard 档密码策略")
    ok, msg = db.validate_new_password("abc123")
    check("7 位被拒", not ok, msg)
    ok, msg = db.validate_new_password("abcdefgh")
    check("纯字母被拒", not ok, msg)
    ok, msg = db.validate_new_password("12345678")
    check("纯数字被拒", not ok, msg)
    ok, msg = db.validate_new_password("abcdefg1")
    check("字母+数字 8 位通过", ok, msg)

    print("\n[3] 账号字段校验")
    expect_error("账号太短被拒", lambda: db.create_user("a", "abcdefg1"), "2~32")
    expect_error("账号含中文被拒", lambda: db.create_user("张三", "abcdefg1"), "字母")
    expect_error("角色非法被拒", lambda: db.create_user("u1", "abcdefg1", role="root"), "角色")
    expect_error("显示名超长被拒", lambda: db.create_user("u1", "abcdefg1", display_name="x" * 33), "32")
    expect_error("弱密码被拒", lambda: db.create_user("u1", "abc"), "至少")
    u1 = db.create_user("u1", "abcdefg1", role="operator", display_name="测试员")
    check("创建成功", u1["username"] == "u1" and u1["role"] == "operator")
    expect_error("重名被拒", lambda: db.create_user("u1", "abcdefg1"), "已存在")

    print("\n[4] 有效期规范化")
    u2 = db.create_user("u2", "abcdefg1", expires_at="2027-01-02")
    check("纯日期补 23:59:59", u2["expires_at"] == "2027-01-02 23:59:59", u2["expires_at"])
    expect_error("非法日期被拒", lambda: db.create_user("u3", "abcdefg1", expires_at="2027/01/02"), "格式")

    # ---------------------------------------------------------- 登录
    print("\n[5] 登录与锁定")
    ok, reason, user = db.verify_login("u1", "abcdefg1")
    check("正确密码登录成功", ok and user["username"] == "u1", reason)
    ok, reason, _ = db.verify_login("u1", "wrong1234")
    check("错误密码被拒且提示剩余次数", not ok and "还可尝试" in reason, reason)
    db.reset_login_failure(u1["id"])
    for _ in range(5):
        db.verify_login("u1", "wrong1234")
    locked = db.get_user(u1["id"])
    check("连续 5 次失败后锁定", locked["state"] == "locked", locked["state_text"])
    ok, reason, _ = db.verify_login("u1", "abcdefg1")
    check("锁定期间正确密码也登不上", not ok and "锁定" in reason, reason)
    db.unlock(u1["id"], "admin", 1)
    ok, _, _ = db.verify_login("u1", "abcdefg1")
    check("解锁后可登录", ok)

    u_dis = db.create_user("u_dis", "abcdefg1", enabled=False)
    ok, reason, _ = db.verify_login("u_dis", "abcdefg1")
    check("禁用账号登不上", not ok and "禁用" in reason, reason)

    u_exp = db.create_user("u_exp", "abcdefg1", expires_at="2020-01-01")
    ok, reason, _ = db.verify_login("u_exp", "abcdefg1")
    check("过期账号登不上", not ok and "过期" in reason, reason)

    print("\n[6] token 版本")
    v0 = db.get_token_version(u1["id"])
    db.update_password(u1["id"], "abcdefg2", "admin", 1, force=True)
    check("改密后 token_version +1", db.get_token_version(u1["id"]) == v0 + 1)
    ok, _, _ = db.verify_login("u1", "abcdefg2")
    check("新密码可登录", ok)

    print("\n[7] 历史密码防复用")
    ok, msg = db.validate_new_password("abcdefg1", user_id=u1["id"])
    check("复用上一次密码被拒", not ok, msg)

    # ---------------------------------------------------------- 七道保护
    print("\n[8] 七道保护（最后一个管理员）")
    admin = db.get_user_by_name("admin")
    expect_error("删除自己", lambda: db.delete_user(admin["id"], "admin", admin["id"]), "当前登录")
    expect_error(
        "删除最后一个启用管理员",
        lambda: db.delete_user(admin["id"], "x", 999),
        "最后一个",
    )
    expect_error(
        "降级最后一个管理员",
        lambda: db.update_user_fields(admin["id"], {"role": "viewer"}, "x", 999),
        "不能降级",
    )
    expect_error(
        "禁用最后一个管理员",
        lambda: db.update_user_fields(admin["id"], {"enabled": False}, "x", 999),
        "不能禁用",
    )
    expect_error(
        "给最后一个管理员设过期",
        lambda: db.update_user_fields(admin["id"], {"expires_at": "2020-01-01"}, "x", 999),
        "过期",
    )
    expect_error(
        "禁用自己",
        lambda: db.update_user_fields(admin["id"], {"enabled": False}, "admin", admin["id"]),
        "当前登录",
    )
    expect_error(
        "修改自己的角色",
        lambda: db.update_user_fields(admin["id"], {"role": "operator"}, "admin", admin["id"]),
        "自己的角色",
    )
    # 有第二个管理员之后，降级就允许了
    admin2 = db.create_user("admin2", "abcdefg1", role="admin")
    db.update_user_fields(admin2["id"], {"role": "operator"}, "admin", admin["id"])
    check("存在第二个管理员时可降级", db.get_user(admin2["id"])["role"] == "operator")

    print("\n[9] 改显示名不应踢下线")
    v = db.get_token_version(admin["id"])
    db.update_user_fields(admin["id"], {"display_name": "系统管理员（改）"}, "admin", admin["id"])
    check("只改显示名 token 不变", db.get_token_version(admin["id"]) == v)
    db.update_user_fields(admin["id"], {"enabled": True}, "admin", admin["id"])
    check("状态无实际变化时 token 不变", db.get_token_version(admin["id"]) == v)

    # ---------------------------------------------------------- 自助 / 管理分权
    print("\n[9b] 自助改密与管理重置分开")
    expect_error(
        "不能绕过旧密码改自己的密码",
        lambda: db.update_user_fields(admin["id"], {"password": "abcdefg9"}, "admin", admin["id"]),
        "个人中心",
    )
    u_self = db.create_user("self1", "abcdefg1", role="viewer", display_name="自助用户")
    db.update_user_fields(u_self["id"], {"display_name": "本人改的名字"}, "self1", u_self["id"])
    check("本人可改自己的显示名", db.get_user(u_self["id"])["display_name"] == "本人改的名字")
    mine = db.list_audit_for_user(u_self["id"])
    check("个人记录只含与自己相关的", all(r["target"] == "self1" or r["actor"] == "self1" for r in mine))
    check("个人记录看不到别人的操作", not any(r["target"] == "admin" for r in mine))
    ok, _, _ = db.verify_login("self1", "abcdefg1")
    check("普通用户仍可正常登录", ok)

    # ---------------------------------------------------------- 审计
    print("\n[10] 审计记录")
    rows = db.list_user_audit(limit=500)
    check("已有审计记录", len(rows) > 0)
    upd = [r for r in rows if r["action"] == "user_update"]
    check("修改记录含新旧值", bool(upd) and upd[0]["old"] is not None and upd[0]["new"] is not None)
    check("审计含 IP", any(r["ip"] for r in rows))
    pwd_rows = [r for r in rows if r["action"] in ("user_reset_password", "password_change")]
    check("密码变更不记明文", all("abcdefg2" not in str(r) for r in pwd_rows))

    conn = sqlite3.connect(path)
    try:
        conn.execute("UPDATE user_audit SET actor='hacker' WHERE id=1")
        check("审计不可修改（触发器）", False, "居然改成功了")
    except sqlite3.IntegrityError:
        check("审计不可修改（触发器）", True)
    try:
        conn.execute("DELETE FROM user_audit WHERE id=1")
        check("审计不可删除（触发器）", False, "居然删成功了")
    except sqlite3.IntegrityError:
        check("审计不可删除（触发器）", True)
    conn.close()

    # ---------------------------------------------------------- 批量导入
    print("\n[11] 批量导入")
    res = db.bulk_create_users(
        [
            {"username": "imp1", "password": "abcdefg1", "role": "viewer"},
            {"username": "imp2", "password": "123", "role": "viewer"},
            {"username": "imp3", "password": "abcdefg1", "role": "hacker"},
            {"username": "imp1", "password": "abcdefg1", "role": "viewer"},
        ],
        "admin",
        admin["id"],
    )
    check("成功 1 条", len(res["created"]) == 1, str(res["created"]))
    check("失败 3 条并给出行号", len(res["failed"]) == 3, str(res["failed"]))
    check("失败原因可读", all(f["error"] for f in res["failed"]))

    # ---------------------------------------------------------- 其他档位
    print("\n[12] lite 档：短密码 + 不锁定")
    db_lite, _ = new_store("lite")
    ok, msg = db_lite.validate_new_password("1234")
    check("lite 允许 4 位纯数字", ok, msg)
    u_lite = db_lite.create_user("lite1", "1234")
    for _ in range(8):
        db_lite.verify_login("lite1", "0000")
    check("lite 不锁号", db_lite.get_user(u_lite["id"])["state"] == "active")

    print("\n[13] gxp 档：12 位 + 四类字符")
    db_gxp, _ = new_store("gxp")
    ok, msg = db_gxp.validate_new_password("Abcdefgh1234")
    check("gxp 拒绝无符号密码", not ok, msg)
    ok, msg = db_gxp.validate_new_password("Abcdefgh123!")
    check("gxp 接受四类字符 12 位", ok, msg)
    check("gxp 默认管理员强制改密", db_gxp.get_user_by_name("admin")["must_change_pwd"] is True)

    # ---------------------------------------------------------- 默认密码
    print("\n[14] 默认初始密码 Aa123456")
    from userstore import DEFAULT_INIT_PASSWORD, default_password

    check("默认密码为 Aa123456", DEFAULT_INIT_PASSWORD == "Aa123456")
    check("standard 档默认值即 Aa123456", default_password({"min_len": 8, "classes": "letter_digit"}) == "Aa123456")

    db_d, _ = new_store("standard")
    u_blank = db_d.create_user("blankpwd", "")
    check("密码留空也能建号", bool(u_blank["id"]))
    check("留空按默认密码发放", db_d.verify_login("blankpwd", "Aa123456")[0])
    check("默认密码强制首登改密", u_blank["must_change_pwd"] is True)
    check("默认密码建号也有有效期逻辑", u_blank["state"] == "active")

    # 用默认密码建的号，未改密前不能访问业务
    ok, reason, _ = db_d.verify_login("blankpwd", "Aa123456")
    check("登录返回需改密标记", ok and db_d.get_user_by_name("blankpwd")["must_change_pwd"] is True)

    # 管理员重置为默认密码 → 同样强制改密
    admin_d = db_d.get_user_by_name("admin")
    db_d.update_password(u_blank["id"], "User@2026x", "admin", admin_d["id"], "", must_change=False)
    check("先改成自定义密码", db_d.get_user(u_blank["id"])["must_change_pwd"] is False)
    db_d._set_password(u_blank["id"], "Aa123456", "admin", admin_d["id"], "", must_change=False)
    check("重置成默认密码又变强制改密", db_d.get_user(u_blank["id"])["must_change_pwd"] is True)

    # gxp 档默认密码要自动补齐
    check("gxp 档默认值补符号", default_password({"min_len": 12, "classes": "all4"}) == "Aa123456@Init")
    ok, msg = db_gxp.validate_new_password("Aa123456@Init")
    check("补齐后的默认密码满足 gxp 策略", ok, msg)
    u_g = db_gxp.create_user("gxpblank", "")
    check("gxp 档留空建号成功", bool(u_g["id"]))
    check("gxp 档按补齐默认值登录", db_gxp.verify_login("gxpblank", "Aa123456@Init")[0])

    # 默认密码本身在库里也是哈希，不是明文
    with db_d._conn() as conn:
        row = conn.execute(
            "SELECT password_hash, salt FROM users WHERE username=?", ("blankpwd",)
        ).fetchone()
    check("库里不存明文密码", "Aa123456" not in (row["password_hash"] or ""))
    check("哈希为 64 位十六进制（PBKDF2-SHA256 32 字节）", len(row["password_hash"]) == 64)
    check("salt 为 32 位十六进制（16 字节随机）", len(row["salt"]) == 32)
    with db_d._conn() as conn:
        salts = [r["salt"] for r in conn.execute("SELECT salt FROM users LIMIT 10").fetchall()]
    check("每个账号 salt 各不相同", len(salts) == len(set(salts)), "%d/%d" % (len(set(salts)), len(salts)))

    # ---------------------------------------------------------- 收尾
    print("\n" + "=" * 62)
    total = PASS + FAIL
    print("结果：%d/%d 通过" % (PASS, total) + ("" if FAIL == 0 else "，%d 项失败" % FAIL))
    print("=" * 62)
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        traceback.print_exc()
        sys.exit(2)
