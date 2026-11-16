---
name: user-admin-template
description: 复用这套用户管理/账号中心底座做新项目，或把认证内核接进已有 Python 项目。适用于新建后台系统要账号登录、权限分级、密码策略、审计追踪、GMP/GxP 合规账号体系的场景；也适用于给已有 Flask/FastAPI/Django 项目补一套可审计的用户管理。触发词：用户管理、账号管理、建个后台、登录注册、权限分级、审计追踪、GxP 账号、复用这套用户管理。
---

# 用户管理模板 · 使用说明

一套零依赖的账号底座：Python 标准库 + SQLite，不装任何包就能跑。
代码在本仓库，`F:\开发\用户管理`。做成两件事：**能独立跑的后台**，和**能搬走的认证内核**。

## 一、先决定用哪种模式

| 场景 | 模式 | 命令 |
|---|---|---|
| 新开一个后台，需要登录界面 + 用户管理页 | `full` | `python scripts/init.py --target ../新项目 --name "车间看板"` |
| 已有 Python 项目（FastAPI/Flask/Django），只想补账号能力 | `core` | `python scripts/init.py --target . --mode core` |
| 非 Python 项目（JS/小程序/前端） | 看 `web/` 和接口表，自己写后端 | 见第四节 |

`full` 产出：`app/` `web/` `tests/` `run.bat` `README.md` `.gitignore`，端口和标题会按 `--name`/`--port` 改好，启动即可用。
`core` 产出：`user_auth/` 下平级的 `userstore.py`、`auth.py`、`selftest.py`，外加一份接入说明。

**做完第一步永远先跑 `selftest.py`**，88 项全绿再写业务代码。它不依赖 Web 层，纯数据层自检，几秒钟出结果。

## 二、这套东西的骨架

```
app/userstore.py   数据层。账号、密码、审计、八道保护全在这里，只依赖标准库
app/auth.py        签名 Token（HMAC-SHA256），payload 带 tv（token_version）
app/server.py      参考 Web 层，标准库 http.server，可以整层替换
web/               界面三件套，纯静态，任何前端都能嵌
tests/selftest.py  数据层自检
scripts/init.py    新项目初始化器
```

三层可分别替换：换框架只动 `server.py`，换界面只动 `web/`，`userstore.py` 一行不用改。**这是复用价值最高的部分，业务项目里不要修改它的内部逻辑**，只调用它的方法。

## 三、核心 API（接进已有项目时看这张表）

```python
from userstore import UserStore, UserError
from auth import TokenSigner

db = UserStore("data/users.db", profile="standard")   # lite / standard / gxp
signer = TokenSigner(secret_path="data/.secret")       # 容器部署务必显式传路径
```

| 方法 | 用途 | 注意 |
|---|---|---|
| `verify_login(username, pwd, ip)` | 登录 | 内置失败计数与锁定，返回 `(ok, user_or_msg)` |
| `create_user(...)` | 建号 | 密码传空字符串 = 发默认密码并强制首登改密 |
| `update_user_fields(id, changes, actor, actor_id, ip)` | 改资料/角色/状态 | 内含八道保护，越界抛 `UserError(403)` |
| `update_password(id, pwd, actor, actor_id, ip)` | 改密 | `token_version +1`，旧会话立即失效 |
| `list_users()` / `stats()` | 列表 / 统计 | `stats()["warnings"]` 带 GxP 体检告警 |
| `list_user_audit(...)` | 审计查询 | 支持 target / action / start / end / limit / offset |
| `count_user_audit(...)` | 审计条数 | 与列表同条件，用于分页 |
| `export_user_audit(...)` | 审计导出 | 不受列表 1000 条限制，上限 5 万 |
| `bulk_create_users(rows, ...)` | 批量导入 | 返回 `created` / `failed`，逐行报错 |

**鉴权中间件必须校验 tv**，否则改密、禁用、强制下线都踢不掉已签发的 token：

```python
payload = signer.verify(token)
if not payload or payload["tv"] != db.get_token_version(payload["uid"]):
    return 401
```

## 四、非 Python 项目怎么用

`userstore.py` 是 Python 的，但**规则和接口语义可以直接照搬**。看这三处：

- `api/users` 系列的请求/响应结构（见 README 第五节接口表）
- `ROLE_META` 和权限判断的位置
- `audit_user_change` 写入的字段（`actor` / `action` / `target` / `old` / `new` / `ip`）

前端那套 `web/` 是纯静态 HTML+CSS+JS，没有构建步骤，可以整体拷进任何前端项目当账号中心页面，只把 `api()` 里的 BASE 指向你的后端。

## 五、八道保护，一条都不能删

这些是防"把自己锁死"的，删掉就会出现没人能进系统的生产事故：

1. 不能删自己
2. 不能禁用自己
3. 不能改自己的角色
4. 不能删最后一个管理员
5. 不能禁用最后一个管理员
6. 不能把最后一个管理员降级
7. 不能改登录名（username 是审计主键，改了历史记录对不上人）
8. 管理员在「系统管理」里改自己密码 → 拒绝（只能走个人中心，必须验旧密码）

## 六、三档安全策略怎么选

| 档位 | 密码要求 | 锁定 | 强制首登改密 | 用在 |
|---|---|---|---|---|
| `lite` | 4 位，无字符要求 | 关 | 关 | 本地开发、车间看板 |
| `standard` | 8 位，字母+数字 | 5 次 / 15 分钟 | 开 | 一般内网后台（默认） |
| `gxp` | 12 位，大小写+数字+符号 | 5 次 / 15 分钟 | 开 | 生产记录配套系统 |

切换只需在构造 `UserStore` 时传 `profile=`，或在 `server.py` 加 `--profile gxp`。

## 七、避坑清单

- **审计查询的时间边界要补全**。`at` 存的是 `YYYY-MM-DD HH:MM:SS`，前端只传日期时必须把结束日补成 `23:59:59`，否则 `at <= '2026-11-16'` 会把当天记录整批漏掉。数据层的 `_norm_day()` 已处理，自己写查询时别忘。
- **导出必须自己留痕**。`audit_export` 这条记录不是可选项——导出不留痕，等于允许任何人把操作记录导走再清场。
- **不要自己做命令行解锁/改密工具**。不需要登录就能改账号状态的入口，在 GxP 审计里等同于后门，会被判定为"存在绕过访问控制的手段"。唯一管理员被锁的正解是等锁定到期，或者用第二个管理员解锁——这也是"至少两个管理员"的实际意义。
- **不要给 `data/` 开公网访问**。`users.db` 里是密码哈希，虽然推不出明文，但拿到库的人可以用字典离线比对。
- **默认密码必须和强制改密绑在一起**。单用默认密码、不强制改，等于全公司同一个口令。
- **账号停用用禁用，不要删除**。删除后审计里只剩一个用户名，查不到这人什么时候建的、什么时候停的。
- **审计表只增不改**。要清理历史就归档到另一张表，不要 `UPDATE` 或 `DELETE`。
- **`username` 不可变更**。显示名可以改，登录名不行，它是审计追踪的关联键。

## 八、和 GxP 的关系（说清楚边界）

这套代码能支撑合规**配置**，但本身不等于通过 21 CFR Part 11。已经具备：唯一账号、强制改密、密码策略、失败锁定、有效期、审计追踪（结构化新旧值、无改删接口）、权限分级、会话撤销。

还缺的（真要做 GxP 生产系统必须补）：电子签名（二次签名）、NTP 时钟同步、定期权限回顾流程与记录、IQ/OQ/PQ 验证文档、账号授权申请单号字段。

角色目前是 3 级（管理员 / 操作员 / 浏览者）。GxP 常见的第 4 级是「审核员（QA）」——能审批、不能管账号，且要与管理员职责分离（管账号的人不能放行批次）。需要时按 `ROLE_META` 的格式增一个即可，权限判断集中在 `server.py` 的路由守卫里。
