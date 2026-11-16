# 给其他项目用的执行提示词

复制下面整段，粘到另一个项目的 AI 会话里即可。它自带仓库地址、命令和避坑点，不依赖任何上下文。

---

```
你的项目要接入一套现成的用户管理底座（账号、密码策略、权限分级、审计追踪）。
仓库：https://github.com/hulitao123/user-admin-template

按下面步骤做，不要凭自己的理解重写一套账号系统。

【第 1 步 · 判断模式】

A) 本项目还没有任何账号体系，需要一个能跑的独立后台
   → full 模式：带登录页、个人中心、用户管理页、审计日志

B) 本项目已有 Python 后端（FastAPI / Flask / Django），只缺账号能力
   → core 模式：只拿数据层三件套，接口自己写

非 Python 项目（Node/小程序/前端）不用 init 脚本，
改读仓库 SKILL.md 第四节，按接口表自己实现，规则照搬。

【第 2 步 · 拉模板到临时目录】

git clone --depth 1 https://github.com/hulitao123/user-admin-template <临时目录>

不要把模板直接 clone 成项目目录，要先 clone 到临时位置再生成，
否则会带上模板的 .git 历史。

【第 3 步 · 生成】

full：
python <临时目录>/scripts/init.py --target <本项目根目录> --name "<项目名>" --port <端口>

core：
python <临时目录>/scripts/init.py --target <本项目根目录> --mode core

生成完删掉临时目录。

【第 4 步 · 必须先验证，全绿才继续】

full：python tests/selftest.py          期望 76/76 通过
core：python user_auth/selftest.py      期望 76/76 通过

不通过就停下报错，不要跳过自检继续写业务代码。

【第 5 步 · 集成时的三条硬约束，违反就是安全漏洞】

1. 鉴权中间件必须校验 tv（token_version）：
     payload = signer.verify(token)
     if not payload or payload["tv"] != db.get_token_version(payload["uid"]):
         return 401
   漏了这一步，改密码、禁用账号、强制下线全都踢不掉已签发的 token。

2. 不要自己拼 SQL 查密码，只用 db.verify_login(username, pwd, ip)，
   它内置失败计数与账号锁定。

3. 审计只通过 db.audit_user_change(...) 写入，不要直接改审计表。

【第 6 步 · 绝对不要做】

- 不要修改 app/userstore.py 的内部逻辑。里面的八道保护是防「把自己锁死」的，
  删任何一条都可能导致没人能进系统。要用就调它的公开方法。
- 不要把 data/ 提交进版本库（.gitignore 已挡住，别去掉）。
- 不要写命令行解锁 / 改密工具。不需要登录就能改账号状态，在 GxP 审计里等同后门。
- 不要改用户的 username。它是审计追踪的关联键，改了历史记录对不上人。
  要改的是 display_name。
- 不要为了开发方便在代码里留「跳过密码校验」的开关。

【详细文档】

仓库 SKILL.md —— 接口速查、八档保护清单、三档策略怎么选、非 Python 项目怎么办
仓库 README.md —— 权限矩阵、完整接口表、GxP 能力边界

【完成的标志】

- 自检 76/76 通过
- 能用初始账号登录，且被强制改密
- 普通角色登录后看不到用户管理菜单，直接调 /api/users* 返回 403
```

---

## 这段提示词为什么这么写

| 写的部分 | 针对的问题 |
|---|---|
| 先判断模式 | 避免在 FastAPI 项目里直接铺一套完整后台 |
| clone 到临时目录 | 避免模板的 git 历史跟着进项目 |
| 强制跑自检 | 76 项覆盖八道保护和审计，改坏了当场暴露 |
| 校验 tv | 这是最容易漏、后果最严重的一条，漏了会话撤销就是摆设 |
| 禁止改 userstore.py | 业务代码越界改数据层，是这类底座被搞坏的常见原因 |
| 禁止命令行解锁 | 曾经加过又删掉的开关，属于绕过访问控制 |
| 写明完成标志 | 让 AI 有明确的验收条件，不是"看起来能跑"就算完 |
