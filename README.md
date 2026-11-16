# 用户管理模板（母本仓库）

一套可直接复用的账号管理底座：**个人自助** 与 **系统管理** 两条线彻底分开，三级角色、八道防锁死保护、三档密码策略、结构化不可篡改审计。

零第三方依赖 —— Python 标准库 + SQLite + 原生 JS，双击就能跑，任何内网机器都能部署。

> **这是母本，不是一次性项目。** 每个新项目都从它复制一份出去，母本自己保持干净、随时能跑。不要在母本上写业务代码。

---

## 零、复用到别的项目

一条命令，两种模式：

```bash
# 模式 A：整套后台（登录界面 + 用户管理页 + 审计），复制完立刻能跑
python scripts/init.py --target ../车间看板 --name "车间看板" --port 8020

# 模式 B：只抽认证内核，接进已有的 FastAPI / Flask / Django 项目
python scripts/init.py --target . --mode core
```

| | 模式 A `full` | 模式 B `core` |
|---|---|---|
| 产出 | `app/` `web/` `tests/` `run.bat` `README.md` `.gitignore` | `user_auth/` 下 `userstore.py` `auth.py` `selftest.py` |
| 适合 | 新开一个独立后台 | 已有项目只要账号能力 |
| 界面 | 自带 | 无，自己写接口 |
| 端口/标题 | 按 `--name` `--port` 自动改好 | —— |

加 `--git` 会顺带 `git init` 并提交一次，直接就是干净的起点。

**复制完第一件事永远是跑自检**：

```bash
python tests/selftest.py        # 模式 A
python user_auth/selftest.py    # 模式 B
```

88 项全绿再写业务代码。它不依赖 Web 层，纯数据层跑，几秒钟出结果。

### 三层可分别替换

| 层 | 文件 | 换掉它的场景 |
|---|---|---|
| 数据层 | `app/userstore.py` | **基本不用换**。零依赖，搬进任何 Python 项目 |
| Web 层 | `app/server.py` | 换 FastAPI/Flask，只抄路由，数据层不动 |
| 界面 | `web/` | 纯静态无构建，整体拷进任何前端项目，改 `api()` 的 BASE 即可 |

### 非 Python 项目

`userstore.py` 是 Python 的，但规则可以照搬：用第五节接口表定契约，用 `ROLE_META` 定角色，用 `audit_user_change` 的字段结构建审计表。前端那套 `web/` 是纯 HTML+CSS+JS，可以直接当账号中心页面用。

### 让别的项目的 AI 帮你接

直接复制 [`USAGE_PROMPT.md`](USAGE_PROMPT.md) 里那段提示词，粘到目标项目的会话里即可。它自带仓库地址、模式判断、命令、验收标准和五条禁止事项，不依赖任何上下文。

---

## 一、为什么这样分层

参考了 Keycloak、Django admin、Casdoor 的做法，它们都把「账号管理」拆成两个互不相通的面：

| 参照 | 它的做法 | 本模板对应 |
|---|---|---|
| Keycloak **Account Console** | 每个用户改自己的资料/密码，必须验旧密码 | 个人中心（所有角色可见） |
| Keycloak **Admin Console** | 管理员建号、改角色、重置他人密码（标记 Temporary，下次登录强制改） | 系统管理 → 用户管理（仅 admin） |
| Django `is_staff` / `is_superuser` | 普通用户进不了后台，后台只对 staff 开放 | 路由层 `required="admin"`，前端菜单只是表象 |
| Casdoor / Keycloak 会话撤销 | 改密或禁用后旧会话立即失效 | `token_version` +1，鉴权层逐请求比对 |

一句话原则：**自己的密码自己改（要旧密码），别人的密码管理员改（不需要旧密码，但强制对方下次改密）。**

### 权限矩阵

| 能力 | 浏览者 viewer | 操作员 operator | 管理员 admin |
|---|:--:|:--:|:--:|
| 登录 | ✅ | ✅ | ✅ |
| 个人中心：改自己的显示名 | ✅ | ✅ | ✅ |
| 个人中心：改自己的密码 | ✅ | ✅ | ✅ |
| 个人中心：看自己的操作记录 | ✅ | ✅ | ✅ |
| 查看用户列表 / 他人信息 | ❌ | ❌ | ✅ |
| 新增 / 编辑 / 删除账号 | ❌ | ❌ | ✅ |
| 重置他人密码 / 解锁 / 强制下线 | ❌ | ❌ | ✅ |
| 全量审计日志 / 导入 / 导出 | ❌ | ❌ | ✅ |

前端隐藏菜单只是体验，**真正的防线在路由层**：`/api/users*` 全部要求 admin，越权直接 403。

---

## 二、两种改密，语义不同

| 场景 | 入口 | 是否验旧密码 | 结果 |
|---|---|:--:|---|
| 我改我自己的 | 个人中心 → 修改密码 | **要** | 我的所有设备下线，拿到新 token |
| 管理员重置他人的 | 用户管理 → 某行「改密」 | 不要 | 旧密码立即失效，**对方下次登录被强制改密** |
| 管理员想改自己的 | —— | —— | 被拒绝，提示去个人中心（防止绕过旧密码校验、保证审计可信） |
| 忘记密码 | 找管理员 | —— | 同上，管理员重置 |

管理员重置后 `must_change_pwd = 1`，对方登录时弹「请修改初始密码」，接口层也会拦截所有业务请求，改完才放行。

---

## 二·五、默认初始密码 Aa123456

**全系统只有一个默认口令 `Aa123456`**：初始管理员、新建账号、重置他人密码，三个入口都是它。新建账号时密码框已经预填，改不改随你；想偷懒就一路点「保存」。为了让这个默认值不变成安全漏洞，后端加了三条硬约束：

| 约束 | 行为 |
|---|---|
| 初始管理员 | 空库首次启动时创建 `admin / Aa123456`，standard 档强制首登改密 |
| 用默认密码建号 | 自动 `must_change_pwd = 1`，**首登不改密就进不去业务**（`/api/users*` 全 403，只放行个人中心） |
| 管理员重置成默认密码 | 同样强制对方下次登录改密，且不受「最近 3 次密码不复用」拦阻（默认密码是公开发放的临时口令） |
| 密码留空 | 建号 / 导入时留空 = 按默认密码发放，不用管理员每次现想 |

严格档（`--profile gxp`，要求 12 位 + 大写/小写/数字/符号）下，默认值自动变成 **`Aa123456@Init`**，否则一保存就被策略挡回来。

> 界面上那句提示会跟着策略变：`已预填默认密码 Aa123456，该账号首次登录会被强制修改`。

---

## 三、快速开始

```bash
# Windows：双击 run.bat
python app/server.py --demo          # 带演示账号
python app/server.py                 # 空库，只有 admin
python app/server.py --port 8080 --profile lite
python app/server.py --reset         # 清库重来
```

打开 http://127.0.0.1:8010 ，初始账号 `admin / Aa123456`。

> **standard 档默认强制首次改密**：登录后必须先把 Aa123456 换掉。演示账号（zhangsan / lisi / wangwu 等）不需要改密，可以直接拿来对比角色差异。
>
> 不想被强制改密：`--profile lite`，或把 `UserStore.SECURITY_PROFILE` 改成 `"lite"`。

演示账号（`--demo` 时生成）：

| 账号 | 密码 | 角色 | 说明 |
|---|---|---|---|
| admin | Aa123456 | 管理员 | 首次登录强制改密 |
| zhangsan | Zhangsan2026 | 管理员 | 可用来测「非唯一管理员」场景 |
| lisi | Lisi2026aa | 操作员 | 30 天后到期 |
| wangwu | Wangwu2026a | 浏览者 | 20 天后到期 |
| sunqi | Sunqi2026x | 操作员 | 已锁定（连续 5 次密码错误） |
| zhaoliu | Zhaoliu2026 | 浏览者 | 已过期 |
| qianba | Qianba2026 | 浏览者 | 已禁用 |

---

## 四、目录结构

```
用户管理/                    ← 母本仓库
├─ scripts/init.py     新项目初始化器（full / core 两种模式）
├─ SKILL.md            给 AI 用的说明书（也可装成本地 Skill）
├─ app/
│  ├─ userstore.py     数据层：建表、哈希、策略、锁定、保护、审计（与框架无关）
│  ├─ auth.py          HMAC 签名 token（含 tv 版本号）
│  └─ server.py        http.server 路由 + 静态文件
├─ web/
│  ├─ index.html       登录 + 个人中心 + 用户管理 + 4 个弹窗
│  ├─ style.css
│  └─ app.js
├─ tests/selftest.py   88 项自检，不依赖 Web 框架
├─ data/users.db       SQLite（首次启动自动生成，不进版本库）
└─ run.bat
```

---

## 五、接口

| 方法 | 路径 | 权限 | 说明 |
|---|---|---|---|
| POST | `/api/login` | 公开 | 返回 token、用户、policy、must_change_pwd |
| POST | `/api/logout` | 登录 | |
| GET | `/api/me` | 登录 | 自己的资料 + 当前策略 |
| PUT | `/api/me` | 登录 | **只能改自己的 display_name** |
| GET | `/api/me/audit` | 登录 | **只含与自己相关**的记录 |
| POST | `/api/password` | 登录 | 自助改密，必须带 `old_password` |
| GET | `/api/users` | admin | 列表（不含密码字段）+ 统计 + policy |
| POST | `/api/users` | admin | 新增 |
| PUT | `/api/users/<id>` | admin | 改资料/角色/启停/有效期/重置密码（五合一） |
| DELETE | `/api/users/<id>` | admin | 删除 |
| GET | `/api/users/audit` | admin | 审计查询，支持 target / action / start / end / limit / offset，返回 `total` |
| GET | `/api/users/audit/export` | admin | 导出审计 CSV（同样的筛选条件，不传条件=全量，**导出动作本身记入审计**） |
| GET | `/api/users/export` | admin | 导出账号清单 CSV（BOM，Excel 不乱码，不含密码） |
| POST | `/api/users/import` | admin | 批量导入 |
| POST | `/api/users/<id>/unlock` | admin | 解除锁定 |
| POST | `/api/users/<id>/kick` | admin | 强制下线 |

> 路由顺序：`/api/users/audit`、`/api/users/export` 必须排在 `/api/users/<id>` 之前，否则 `export` 会被当成 id 去 `int()`。

---

## 六、八道保护，一条都不能删

这八条是防"把自己锁死"的，删掉任何一条都可能出现"没人能进系统"的生产事故：

1. 删除最后一个启用管理员 → 拒
2. 降级最后一个启用管理员 → 拒
3. 禁用最后一个启用管理员 → 拒
4. 删除自己 → 拒
5. 禁用自己 → 拒
6. 删除/禁用/改密后旧 token 立即失效（`token_version`）
7. 把最后一个启用管理员设成已过期 → 拒
8. **修改自己的角色 → 拒**（原方案没有；降级自己等于当场交出管理权，回不来）

判断依据是「**操作完成后的最终状态**」，不是「这次改了哪个字段」：

```python
final_role    = fields.get("role", target["role"])
final_enabled = fields.get("enabled", target["enabled"])
final_expires = fields.get("expires_at", target["expires_at"])
```

---

## 七、三档安全策略

改一行切换，业务代码不动：`UserStore.SECURITY_PROFILE = "standard"`（或启动参数 `--profile`）。

| 项 | lite | standard（默认） | gxp |
|---|---|---|---|
| 密码最短长度 | 4 | 8 | 12 |
| 字符要求 | 无 | 字母 + 数字 | 大写 + 小写 + 数字 + 符号 |
| 历史密码防复用 | 不查 | 最近 3 次 | 最近 5 次 |
| 强制轮换 | 不轮换 | 不轮换 | 90 天 |
| 登录失败锁定 | 不锁 | 5 次锁 15 分钟 | 5 次锁 30 分钟 |
| 默认 admin 强制改密 | 否 | 是 | 是 |

`lite` 给车间看板/内网小工具，`standard` 给有外包进出的辅助后台，`gxp` 给生产记录配套。
⚠️ `gxp` 档也不等于通过 21 CFR Part 11：还缺电子签名、NTP 时钟、IQ/OQ/PQ、定期权限回顾。

---

## 七·五、密码在库里长什么样

**打不开。库里没有密码，只有密码的「指纹」。**

| 项 | 实现 |
|---|---|
| 算法 | PBKDF2-HMAC-SHA256，`ITERATIONS = 200_000` |
| 盐 | 每个账号独立 16 字节随机盐（`secrets.token_hex(16)`），存在 `salt` 列 |
| 存储 | `password_hash` 64 位十六进制（32 字节摘要）+ `salt` 32 位十六进制 |
| 比对 | `secrets.compare_digest`（常量时间，防时序侧信道） |
| 明文 | 全表、全库、审计表、导出文件里**都没有** |

真实库里读出来是这样（`SELECT * FROM users`）：

```
admin  | 21f68b4d...  | 6518af14f9cebff7...
sunqi  | c582b4d7...  | 55093b0894c95010...
```

所以：

- ✅ **看不到密码本身**，也推不回去（PBKDF2 是单向函数）
- ✅ 同一个密码，两个账号的哈希完全不同（盐不同），彩虹表无效
- ⚠️ 但**能验证某个猜测对不对**——拿到库的人可以「试一遍常用密码」，把哈希和猜测值比对

最后一条才是真风险，也是制药行业最忌讳的一点：**默认密码是公开的**，攻击者拿到库，几秒钟就能筛出「谁的密码还是 Aa123456」。这就是为什么代码里把「用默认密码」和「强制首登改密」焊死在一起——不给人偷懒的机会。

真要再上一层：

| 措施 | 怎么做 |
|---|---|
| 提高单次哈希成本 | `ITERATIONS` 调到 600_000（代价是登录慢约 100ms） |
| 加密库文件 | SQLite 本身不加密，换 SQLCipher，或把 `data/` 放进 BitLocker 卷 / EFS 加密目录 |
| 限制库文件权限 | 只给运行服务的系统账号读写，别放共享盘 |
| 备份同样对待 | 备份文件带哈希，等同于密码表，按同样级别保管 |
| 密码永不出现在日志 | 已实现：审计只记「密码已重置」，接口不回传 `password*` 字段 |

---

## 八、接进自己的项目

数据层与框架无关，`userstore.py` 可以原样搬走：

| 本模板写法 | FastAPI | Flask |
|---|---|---|
| `{"ok": True, **data}` | `return {"ok": True, **data}` | `jsonify(...)` |
| `raise UserError(msg, 403)` | `raise HTTPException(403, msg)` | `return jsonify(...), 403` |
| `self._auth("admin")` | `Depends(require_admin)` | 装饰器 |
| `self._client_ip()` | `request.client.host` | `request.remote_addr` |

前端 `web/app.js` 只依赖三个东西：`api()`（带 token、401 回登录）、`esc()`（防 XSS）、`toast()`。接进现有后台时替换这三个即可。

改完先跑自检：

```bash
python tests/selftest.py        # 全部用例
python tests/selftest.py -v     # 逐步输出
```

覆盖：三档策略、历史密码、失败锁定、有效期、token 版本、八道保护、自助/管理分权、默认密码发放、密码哈希形态、审计新旧值、审计防篡改、批量导入。

---

## 九、审计

- `old_value` / `new_value` 存**结构化快照**，不是自由文本；前端能压成「显示名：张三（灌装车间） → 张三（灌装班长）」
- 密码变更永不记明文，只记「密码已重置」
- SQLite 触发器兜底：`UPDATE` / `DELETE` 直接 `RAISE(ABORT)`，应用层也改不了
- 每条都带 IP（反代后请覆盖成真实来源）
- 普通用户只能看自己的记录（`actor_id` 或 `target_id` 命中自己）

### 查询：按动作 + 人 + 时间范围

四个条件可任意组合，服务端分页，一次 50 条：

| 参数 | 含义 | 说明 |
|---|---|---|
| `action` | 动作类型 | 精确匹配 |
| `target` | 账号 / 操作人 | 模糊匹配，两个字段都查 |
| `start` / `end` | 时间范围 | 可只传日期，**结束日自动补到 23:59:59**，否则当天记录会整批漏掉 |
| `limit` / `offset` | 分页 | `limit` 上限 1000，是接口保护，不是数据上限 |

响应带 `total`，前端据此算页数。

### 导出：给检查官的那份材料

`GET /api/users/audit/export` 走同一套筛选条件，不传条件就是全量。产出是带 BOM 的 UTF-8 CSV，Excel 打开不乱码，动作和字段名都是中文（`角色: 浏览者 → 操作员`），密码只写「已变更」。

**导出这个动作本身会写一条 `audit_export` 审计**，记录导了多少条、筛选条件是什么。理由很直接：如果导出不留痕，任何人都能把全部操作记录导走再删掉现场，审计就失去意义。

> 导出上限 5 万条（`export_user_audit(max_rows=...)`）。真要导更多，按时间分段导，别一次拉全库。

---

## 十、故意不做的事

| 不做 | 原因 |
|---|---|
| 权限矩阵（角色 × 权限点） | 十几个操作三级角色够分；配置成本高于收益，配错比没权限更危险 |
| 密码重置审批流 | 单/双管理员系统里只会增加卡死概率，不降低真实风险 |
| 邮件找回密码 | 内网系统没有 SMTP，走管理员重置 + 强制改密更可控 |
| 短信/MFA | 需要外部通道，属另一层；真要做建议上 Keycloak/Casdoor 而不是自己写 |

真需要细粒度权限时的最小改法：保留角色卡片做「粗粒度主角色」，另加 `user_extra_perms` 表存单点权限，鉴权时 `role 够 or 单点命中` 二选一，老逻辑一行不改。

---

## 十一、上线前检查

- [ ] 改掉默认密码 `Aa123456`，或确认 `force_change_default` 生效
- [ ] 至少两个实名管理员，然后禁用 `admin`
- [ ] 生产环境把 `data/.secret` 换成随机密钥并限制权限
- [ ] HTTPS（否则 token 会被截获）
- [ ] 反代后覆盖 `_client_ip()`，否则审计 IP 全是空
- [ ] 定期导出并归档审计表（清理前先 `DROP TRIGGER`，清完重建并留痕）
- [ ] 数据库文件纳入备份
