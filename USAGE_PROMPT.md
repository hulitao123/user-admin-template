# 给其他项目用的提示词

仓库：https://github.com/hulitao123/user-admin-template （公开）

- 已有用户管理 → 用提示词 A（对照审查，只修有问题的）
- 新项目 / 要整套后台 → 用提示词 B

---

## 提示词 A · 对照审查

```
参考仓库：https://github.com/hulitao123/user-admin-template

本项目已有用户管理，不要推倒重来，也不要换技术栈。
先对照它审查现有实现，再决定改哪里。

逐条查，输出差异清单（有问题 / 可接受 / 它不如我们）：
1. 密码存储：明文、MD5 或无盐 SHA256 → 有问题
2. 会话撤销：改密码、禁用账号后旧 token 还能用 → 有问题
3. 越权：非管理角色直接调管理接口能被通过 → 有问题（前端藏菜单不算拦住）
4. 后门：存在跳过密码校验的开关、命令行改密/解锁工具 → 有问题
5. 审计：账号变更记录能被 UPDATE / DELETE 改掉 → 有问题
6. 锁死：最后一个管理员能被删、禁用或降级 → 有问题

这 6 项必须全部合格，具体怎么实现你定。
清单里标「有问题」的必须修，其余部分不要动。
改完说明：改前什么表现、改后什么表现、怎么验证的。
```

---

## 提示词 B · 直接生成

```
仓库：https://github.com/hulitao123/user-admin-template

git clone --depth 1 <仓库> <临时目录>   # 不要直接克隆成项目目录

有 Python 后端、只缺账号能力：
  python <临时目录>/scripts/init.py --target <项目根目录> --mode core
要一套能跑的后台（登录页 + 个人中心 + 用户管理 + 审计）：
  python <临时目录>/scripts/init.py --target <项目根目录> --name "<项目名>" --port <端口>

生成后删掉临时目录，先过自检再写业务代码（期望 88/88）。

集成时别漏：鉴权要校验 token_version，否则改密码踢不掉旧会话；
登录只走 db.verify_login()，内含失败锁定；审计只通过 db.audit_user_change() 写。
不要改 app/userstore.py 内部逻辑（八道防锁死保护），不要改 username，不要留密码校验开关。

初始账号 admin / Aa123456，首次登录强制改密。
```
