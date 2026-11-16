# 给其他项目用的提示词

仓库：https://github.com/hulitao123/user-admin-template （公开）

直接复制全文，粘到目标项目的 AI 会话里。不依赖任何上下文。

---

```
你的项目要接入一套现成的用户管理底座（账号、密码策略、权限分级、审计追踪）。
仓库：https://github.com/hulitao123/user-admin-template
按以下步骤执行，不要自己重写一套账号系统。

【1. 克隆到临时目录】
git clone --depth 1 https://github.com/hulitao123/user-admin-template <临时目录>
不要直接克隆成项目目录（会带上模板的 git 历史），生成完删掉临时目录。

【2. 生成】
已有后端、只缺账号能力（只装数据层）：
  python <临时目录>/scripts/init.py --target <项目根目录> --mode core
要一套能跑的后台（登录页、个人中心、用户管理、审计）：
  python <临时目录>/scripts/init.py --target <项目根目录> --name "<项目名>" --port <端口>
非 Python 项目不用 init 脚本，读仓库 SKILL.md 第四节照接口表实现。

【3. 必须验证，全绿才继续】
core: python user_auth/selftest.py      期望 88/88
full: python tests/selftest.py          期望 88/88
不通过就停下报错，不要跳过自检写业务代码。

【4. 三条硬约束，违反就是安全漏洞】
1) 鉴权中间件必须校验 token 版本：
   if not payload or payload["tv"] != db.get_token_version(payload["uid"]): return 401
   漏了这步，改密、禁用、强制下线都踢不掉已签发的 token。
2) 不要自己拼 SQL 查密码，只用 db.verify_login(username, pwd, ip)，它内置失败计数与锁定。
3) 审计只通过 db.audit_user_change(...) 写入，不要直接改审计表。

【5. 绝对不要做】
- 不要改 app/userstore.py 内部逻辑，八道保护是防锁死的，删一条可能没人能进系统
- 不要把 data/ 提交进版本库
- 不要写命令行解锁/改密工具（免登录改账号状态等于后门）
- 不要改 username（审计关联键），要改改 display_name
- 不要留「跳过密码校验」的开发开关

【6. 完成标志】
自检 88/88；初始账号登录被强制改密；普通角色看不到用户管理菜单，直接调 /api/users* 返回 403。

文档：SKILL.md（接口速查、八道保护、三档选型）、README.md（权限矩阵、接口表、GxP 边界）
```

---

## 如果你只是想查现有系统的漏洞

项目已经有用户管理、不打算接入这套底座时，用下面这段：

```
参考 https://github.com/hulitao123/user-admin-template 审查本项目现有用户管理，不要推倒重来。
逐条查并输出差异清单：密码是否明文/MD5/无盐 SHA256；改密或禁用后旧 token 是否还能用；
非管理角色直接调管理接口能否通过；有无跳过密码校验的开关或命令行改密工具；
审计记录能否被 UPDATE/DELETE 改掉；最后一个管理员能否被删、禁用或降级。
标「有问题」的必须修，其余不要动。改完说明改前表现、改后表现、怎么验证的。
```

---

初始账号 `admin / Aa123456`，首次登录强制修改。
三档策略 `lite / standard / gxp`，gxp 档默认密码为 `Aa123456@Init`，同样首登强制改。
