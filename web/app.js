/* ============================================================
   用户管理模板 · 前端逻辑
   依赖：仅浏览器原生 API。所有接口走 apiFetch，401 自动回登录。
   ============================================================ */
(function () {
  "use strict";

  var STATE = {
    token: localStorage.getItem("um_token") || "",
    me: null,
    users: [],
    stats: null,
    policy: null,
    q: "",
    role: "",
    editing: null,
    pwdTarget: null,
    forced: false,
    importRows: []
  };

  var ACTIONS = {
    user_create: { label: "新增用户", cls: "create" },
    user_update: { label: "修改资料", cls: "" },
    user_reset_password: { label: "重置密码", cls: "pwd" },
    password_change: { label: "修改密码", cls: "pwd" },
    user_delete: { label: "删除用户", cls: "delete" },
    user_unlock: { label: "解除锁定", cls: "" },
    user_kick: { label: "强制下线", cls: "" },
    user_lock: { label: "自动锁定", cls: "delete" },
    user_import: { label: "批量导入", cls: "create" },
    user_export: { label: "导出清单", cls: "" },
    audit_export: { label: "导出审计", cls: "" }
  };

  var FIELD_LABEL = {
    display_name: "显示名",
    role: "角色",
    enabled: "状态",
    expires_at: "有效期",
    password: "密码",
    locked_until: "锁定",
    online: "在线",
    exported: "导出",
    created: "账号"
  };

  /* ---------------------------------------------------------- 基础工具 */
  function $(id) { return document.getElementById(id); }

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function toast(msg, type) {
    var host = $("toastHost");
    var el = document.createElement("div");
    el.className = "toast " + (type || "");
    el.textContent = msg;
    host.appendChild(el);
    setTimeout(function () {
      el.style.transition = "opacity .2s, transform .2s";
      el.style.opacity = "0";
      el.style.transform = "translateY(6px)";
      setTimeout(function () { el.remove(); }, 220);
    }, type === "error" ? 3600 : 2200);
  }

  function showErr(id, msg) { $(id).textContent = msg || ""; }

  /* 统一的二次确认（不用浏览器原生 confirm，样式一致且可 Esc 取消） */
  function confirmBox(title, text, okText, danger) {
    return new Promise(function (resolve) {
      var wrap = document.createElement("div");
      wrap.className = "modal open";
      wrap.style.zIndex = "80";
      wrap.innerHTML =
        '<div class="modal-box w420" role="dialog" aria-modal="true">' +
          '<div class="modal-head"><h2>' + esc(title) + "</h2></div>" +
          '<div class="modal-body"><p class="confirm-text">' + esc(text) + "</p></div>" +
          '<div class="modal-foot"><button class="btn" data-no>取消</button>' +
          '<button class="btn ' + (danger ? "danger-solid" : "primary") + '" data-yes>' +
          esc(okText || "确定") + "</button></div>" +
        "</div>";
      document.body.appendChild(wrap);

      function done(ok) {
        document.removeEventListener("keydown", onKey);
        wrap.remove();
        resolve(ok);
      }
      function onKey(e) {
        if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); done(false); }
        else if (e.key === "Enter") { e.preventDefault(); e.stopPropagation(); done(true); }
      }
      wrap.querySelector("[data-no]").onclick = function () { done(false); };
      wrap.querySelector("[data-yes]").onclick = function () { done(true); };
      wrap.addEventListener("click", function (e) { if (e.target === wrap) done(false); });
      document.addEventListener("keydown", onKey, true);
      setTimeout(function () { wrap.querySelector("[data-yes]").focus(); }, 30);
    });
  }

  function api(path, opts) {
    opts = opts || {};
    var headers = Object.assign({}, opts.headers || {});
    if (STATE.token) headers["Authorization"] = "Bearer " + STATE.token;
    var body = opts.body;
    if (body && typeof body !== "string") {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(body);
    }
    return fetch(path, { method: opts.method || "GET", headers: headers, body: body })
      .then(function (resp) {
        if (resp.status === 401 && path !== "/api/login") {
          logoutLocal(true);
          throw new Error("登录已失效，请重新登录");
        }
        return resp.json().catch(function () { return {}; }).then(function (data) {
          if (!resp.ok || data.ok === false) throw new Error(data.error || ("请求失败 HTTP " + resp.status));
          return data;
        });
      });
  }

  function fmtTime(s) {
    if (!s) return "";
    var p = String(s).split(" ");
    var d = (p[0] || "").slice(5);
    var t = (p[1] || "").slice(0, 5);
    return t ? d + " " + t : d;
  }

  function fmtLogin(s) {
    if (!s) return '<span class="muted">从未登录</span>';
    var p = String(s).split(" ");
    return '<div class="time-cell">' + esc((p[0] || "").slice(5)) + "<small>" + esc((p[1] || "").slice(0, 5)) + "</small></div>";
  }

  function initial(u) {
    var s = (u.display_name || u.username || "?").trim();
    return esc(s.slice(0, 1).toUpperCase());
  }

  function todayStr() {
    var d = new Date();
    var m = String(d.getMonth() + 1).padStart(2, "0");
    var day = String(d.getDate()).padStart(2, "0");
    return d.getFullYear() + "-" + m + "-" + day;
  }

  /* ---------------------------------------------------------- 登录 / 登出 */
  function logoutLocal(silent) {
    STATE.token = "";
    STATE.me = null;
    STATE.users = [];
    localStorage.removeItem("um_token");
    $("appView").classList.add("hidden");
    $("loginView").classList.remove("hidden");
    if (!silent) toast("已退出登录", "success");
  }

  function doLogout() {
    api("/api/logout", { method: "POST" }).catch(function () {}).then(function () { logoutLocal(); });
  }

  function isAdmin() {
    return !!(STATE.me && STATE.me.role === "admin");
  }

  function applyRoleUI() {
    var admin = isAdmin();
    Array.prototype.forEach.call(document.querySelectorAll("[data-admin]"), function (el) {
      el.classList.toggle("hidden", !admin);
    });
  }

  function showView(name) {
    if (name === "users" && !isAdmin()) name = "profile";
    STATE.view = name;
    $("viewUsers").classList.toggle("hidden", name !== "users");
    $("viewProfile").classList.toggle("hidden", name !== "profile");
    Array.prototype.forEach.call(document.querySelectorAll(".nav-item"), function (b) {
      b.classList.toggle("active", b.dataset.nav === name);
    });
    if (name === "users") loadUsers();
    else loadProfile();
  }

  function enterApp() {
    $("loginView").classList.add("hidden");
    $("appView").classList.remove("hidden");
    applyRoleUI();
    renderMe();
    // 还没改初始密码时不要拉数据：后端会 403，界面会空一片
    if (STATE.me && STATE.me.must_change_pwd) return;
    showView(isAdmin() ? "users" : "profile");
  }

  function renderMe() {
    var me = STATE.me || {};
    $("meName").textContent = me.display_name || me.username || "–";
    $("meRole").textContent = me.role_label || "–";
    $("meAvatar").textContent = initial(me);
    $("meAvatar").className = "avatar sm role-" + (me.role || "viewer");
    var p = STATE.policy || {};
    $("policyChip").innerHTML = "安全档位 <b>" + esc(p.profile || "–") + "</b>";
    $("policyChip").title = p.hint || "";
    $("policyHint").textContent = p.hint || "–";
    $("policyLock").textContent = p.lock_after
      ? "连续 " + p.lock_after + " 次错误锁定 " + p.lock_minutes + " 分钟"
      : "不锁定（内网轻量档）";
  }

  $("loginForm").addEventListener("submit", function (ev) {
    ev.preventDefault();
    showErr("loginErr", "");
    var btn = $("loginBtn");
    btn.disabled = true;
    btn.textContent = "登录中…";
    api("/api/login", {
      method: "POST",
      body: { username: $("loginUser").value.trim(), password: $("loginPwd").value }
    }).then(function (d) {
      STATE.token = d.token;
      STATE.me = d.user;
      STATE.policy = d.policy;
      localStorage.setItem("um_token", d.token);
      $("loginPwd").value = "";
      enterApp();
      if (d.must_change_pwd) {
        toast("首次登录，请先修改密码", "error");
        openPwdModal(d.user, true);
      }
    }).catch(function (e) {
      showErr("loginErr", e.message);
    }).then(function () {
      btn.disabled = false;
      btn.textContent = "登录";
    });
  });

  $("logoutBtn").addEventListener("click", doLogout);

  Array.prototype.forEach.call(document.querySelectorAll(".nav-item"), function (b) {
    b.addEventListener("click", function () {
      if (b.dataset.nav === "audit") { openAudit(); return; }
      showView(b.dataset.nav);
    });
  });

  /* ---------------------------------------------------------- 列表渲染 */
  function loadUsers() {
    return api("/api/users").then(function (d) {
      STATE.users = d.users;
      STATE.stats = d.stats;
      STATE.policy = d.policy;
      if (d.me) STATE.me = d.me;
      renderMe();
      renderStats();
      renderGxpAlerts();
      renderTable();
    }).catch(function (e) {
      toast(e.message, "error");
    });
  }

  function renderStats() {
    var s = STATE.stats || { total: 0, enabled: 0, locked: 0, expired: 0, roles: {} };
    var roles = s.roles || {};
    var html = "";
    html += '<div class="stat"><b>' + s.total + "</b><span>账号总数</span></div>";
    html += '<div class="stat"><b>' + s.enabled + "</b><span>已启用</span></div>";
    html += '<div class="stat"><b>' + (roles.admin || 0) + '</b><span><i class="role-dot admin"></i>管理员</span></div>';
    html += '<div class="stat"><b>' + (roles.operator || 0) + '</b><span><i class="role-dot operator"></i>操作员</span></div>';
    html += '<div class="stat"><b>' + (roles.viewer || 0) + '</b><span><i class="role-dot viewer"></i>浏览者</span></div>';
    if (s.locked) html += '<div class="stat alert"><b>' + s.locked + "</b><span>锁定</span></div>";
    if (s.expired) html += '<div class="stat danger"><b>' + s.expired + "</b><span>已过期</span></div>";
    $("statbar").innerHTML = html;
  }

  function renderGxpAlerts() {
    var box = $("gxpAlerts");
    var list = (STATE.stats && STATE.stats.warnings) || [];
    if (!list.length) {
      box.innerHTML = "";
      box.classList.add("hidden");
      return;
    }
    box.innerHTML = list
      .map(function (w) {
        return (
          '<div class="gxp-alert ' + (w.level === "warn" ? "warn" : "info") + '">' +
          '<span class="gxp-ico">!</span>' +
          '<span class="gxp-body"><b>' + esc(w.title) + "</b>" + esc(w.text) + "</span>" +
          "</div>"
        );
      })
      .join("");
    box.classList.remove("hidden");
  }

  function filtered() {
    var q = STATE.q.toLowerCase();
    return STATE.users.filter(function (u) {
      if (STATE.role && u.role !== STATE.role) return false;
      if (!q) return true;
      return (u.username + " " + (u.display_name || "")).toLowerCase().indexOf(q) >= 0;
    });
  }

  function expCell(u) {
    if (!u.expires_at) return '<span class="exp-none">—</span>';
    var d = u.expires_at.slice(0, 10);
    var cls = "time-cell";
    if (d < todayStr()) cls += " exp-past";
    else if (d <= addDays(todayStr(), 7)) cls += " exp-soon";
    return '<span class="' + cls + '">' + esc(d) + "</span>";
  }

  function addDays(base, n) {
    var d = new Date(base + "T00:00:00");
    d.setDate(d.getDate() + n);
    return d.getFullYear() + "-" + String(d.getMonth() + 1).padStart(2, "0") + "-" + String(d.getDate()).padStart(2, "0");
  }

  function renderTable() {
    var list = filtered();
    var me = STATE.me || {};
    var rows = list.map(function (u) {
      var isMe = u.id === me.id;
      var badge = "";
      if (u.state === "locked") badge = '<span class="badge lock">' + esc(u.state_text) + "</span>";
      else if (u.state === "expired") badge = '<span class="badge expired">已过期</span>';
      else if (u.state === "disabled") badge = '<span class="badge expired">已禁用</span>';

      var acts = ['<button data-act="edit">编辑</button>', '<button data-act="pwd">改密</button>'];
      if (u.state === "locked") acts.push('<button data-act="unlock">解锁</button>');
      if (!isMe) {
        if (u.enabled) acts.push('<button data-act="kick">下线</button>');
        acts.push('<span class="sep"></span>');
        acts.push('<button data-act="del" class="danger">删除</button>');
      }

      return (
        '<tr data-id="' + u.id + '">' +
          '<td class="c-id">' + u.id + "</td>" +
          "<td><div class=\"user-cell\">" +
            '<span class="avatar role-' + esc(u.role) + '">' + initial(u) + "</span>" +
            '<div class="user-meta"><div class="user-name">' + esc(u.display_name || u.username) +
              (isMe ? '<span class="me-tag">我</span>' : "") +
            "</div>" +
            '<div class="user-login">@' + esc(u.username) + "</div></div>" +
          "</div></td>" +
          '<td><span class="pill ' + esc(u.role) + '">' + esc(u.role_label) + "</span></td>" +
          '<td><div class="state-cell">' +
            '<div class="switch-row"><span class="switch"><input type="checkbox" data-act="toggle"' +
              (u.enabled ? " checked" : "") + (isMe ? " disabled" : "") + "><i></i></span>" +
              "<span>" + (u.enabled ? "启用" : "禁用") + "</span></div>" +
            badge +
          "</div></td>" +
          "<td>" + fmtLogin(u.last_login_at) + "</td>" +
          "<td>" + expCell(u) + "</td>" +
          '<td><div class="row-actions">' + acts.join("") + "</div></td>" +
        "</tr>"
      );
    });

    $("userRows").innerHTML = rows.join("");
    $("emptyState").classList.toggle("hidden", list.length > 0);
    $("tableCount").textContent = "共 " + list.length + " 个账号" +
      (list.length !== STATE.users.length ? "（总 " + STATE.users.length + "）" : "");
  }

  $("q").addEventListener("input", function () {
    STATE.q = this.value.trim();
    renderTable();
  });

  $("roleFilter").addEventListener("click", function (ev) {
    var btn = ev.target.closest(".chip");
    if (!btn) return;
    STATE.role = btn.dataset.role;
    Array.prototype.forEach.call(this.querySelectorAll(".chip"), function (c) {
      c.classList.toggle("active", c === btn);
    });
    renderTable();
  });

  $("userRows").addEventListener("click", function (ev) {
    var btn = ev.target.closest("button[data-act]");
    if (!btn) return;
    var id = Number(btn.closest("tr").dataset.id);
    var u = STATE.users.filter(function (x) { return x.id === id; })[0];
    if (!u) return;
    var act = btn.dataset.act;
    if (act === "edit") openUserModal(u);
    else if (act === "pwd") openPwdModal(u, false);
    else if (act === "unlock") unlockUser(u);
    else if (act === "kick") kickUser(u);
    else if (act === "del") deleteUser(u);
  });

  $("userRows").addEventListener("change", function (ev) {
    var inp = ev.target.closest('input[data-act="toggle"]');
    if (!inp) return;
    var id = Number(inp.closest("tr").dataset.id);
    var u = STATE.users.filter(function (x) { return x.id === id; })[0];
    var want = inp.checked;
    if (!u) return;
    if (!want) {
      confirmBox(
        "禁用账号",
        "禁用「" + (u.display_name || u.username) + "」后该账号将立即无法登录，正在使用的会话也会失效。",
        "确认禁用",
        true
      ).then(function (ok) {
        if (!ok) { inp.checked = true; return; }
        api("/api/users/" + id, { method: "PUT", body: { enabled: false } })
          .then(function () { toast("已禁用该账号", "success"); return loadUsers(); })
          .catch(function (e) { inp.checked = true; toast(e.message, "error"); });
      });
      return;
    }
    api("/api/users/" + id, { method: "PUT", body: { enabled: true } })
      .then(function () {
        toast("已启用该账号", "success");
        return loadUsers();
      })
      .catch(function (e) {
        inp.checked = false;
        toast(e.message, "error");
      });
  });

  /* ---------------------------------------------------------- 用户弹窗 */
  var editingUser = null;

  function renderRoleCards(selected, lockSelf) {
    var roles = (STATE.policy && STATE.policy.roles) || [];
    $("roleCards").innerHTML = roles.map(function (r) {
      return (
        '<button type="button" class="role-card' + (r.key === selected ? " on" : "") +
        '" data-role="' + esc(r.key) + '"' + (lockSelf ? " disabled" : "") +
        "><b>" + esc(r.label) + "</b><i>" + esc(r.detail) + "</i></button>"
      );
    }).join("");
    $("roleHint").textContent = lockSelf
      ? "不能修改自己的角色 —— 请让另一位管理员操作，否则会当场失去管理权限"
      : "";
  }

  $("roleCards").addEventListener("click", function (ev) {
    var card = ev.target.closest(".role-card");
    if (!card) return;
    Array.prototype.forEach.call(this.querySelectorAll(".role-card"), function (c) {
      c.classList.toggle("on", c === card);
    });
  });

  function selectedRole() {
    var on = $("roleCards").querySelector(".role-card.on");
    return on ? on.dataset.role : "";
  }

  function openUserModal(u) {
    editingUser = u || null;
    showErr("userFormErr", "");
    $("userModalTitle").textContent = u ? "编辑用户" : "新增用户";
    $("ufUsername").value = u ? u.username : "";
    $("ufUsername").disabled = !!u;
    $("ufDisplay").value = u ? u.display_name || "" : "";
    $("ufExpires").value = u && u.expires_at ? u.expires_at.slice(0, 10) : "";
    $("ufEnabled").checked = u ? !!u.enabled : true;
    $("ufEnabled").disabled = !!(u && STATE.me && u.id === STATE.me.id);
    renderRoleCards(u ? u.role : "viewer", !!(u && STATE.me && u.id === STATE.me.id));

    var p = STATE.policy || {};
    var dft = p.default_password || "Aa123456";
    if (u) {
      $("ufPwd").value = "";
      $("ufPwd2").value = "";
      $("ufPwdReq").classList.add("hidden");
      $("ufPwd2Req").classList.add("hidden");
      $("pwdHint").textContent = "留空 = 不修改密码；如需强制该用户下次登录改密，用「改密」按钮";
    } else {
      $("ufPwd").value = dft;
      $("ufPwd2").value = dft;
      $("ufPwdReq").classList.remove("hidden");
      $("ufPwd2Req").classList.remove("hidden");
      $("pwdHint").textContent =
        "已预填默认密码 " + dft + "，该账号首次登录会被强制修改（" + (p.hint || "") + "）";
    }
    updateMeter("ufPwd", "pwdMeter");
    updateEnabledText();
    openModal("modalUser", u ? "ufDisplay" : "ufUsername");
  }

  function updateEnabledText() {
    $("ufEnabledText").textContent = $("ufEnabled").checked ? "启用" : "禁用";
  }
  $("ufEnabled").addEventListener("change", updateEnabledText);

  function updateMeter(inputId, meterId) {
    var p = STATE.policy || { min_len: 4, classes: "none" };
    var v = $(inputId).value;
    var classes = 0;
    if (/[a-z]/.test(v)) classes++;
    if (/[A-Z]/.test(v)) classes++;
    if (/[0-9]/.test(v)) classes++;
    if (/[^A-Za-z0-9]/.test(v)) classes++;
    var score = 0;
    if (v.length >= Math.max(4, p.min_len)) score++;
    if (v.length >= 12) score++;
    if (classes >= 2) score++;
    if (classes >= 3) score++;
    if (!v) score = 0;
    var colors = ["#e5e8ee", "#cf3b3b", "#d98b18", "#2f8f6b", "#12855a"];
    var widths = ["0%", "25%", "50%", "75%", "100%"];
    $(meterId).style.width = widths[score];
    $(meterId).style.background = colors[score];
  }

  ["ufPwd", "pfNew", "meNew"].forEach(function (id) {
    $(id).addEventListener("input", function () {
      updateMeter(id, id === "ufPwd" ? "pwdMeter" : id === "pfNew" ? "pfMeter" : "meMeter");
    });
  });

  $("btnNew").addEventListener("click", function () { openUserModal(null); });

  $("ufSubmit").addEventListener("click", function () {
    showErr("userFormErr", "");
    var username = $("ufUsername").value.trim();
    var display = $("ufDisplay").value.trim();
    var pwd = $("ufPwd").value;
    var pwd2 = $("ufPwd2").value;
    var role = selectedRole();
    var exp = $("ufExpires").value;
    var enabled = $("ufEnabled").checked;
    var p = STATE.policy || {};

    if (!editingUser && !/^[A-Za-z0-9_.\-]{2,32}$/.test(username)) {
      return showErr("userFormErr", "登录账号需 2~32 位，仅限字母、数字、下划线、点和短横线");
    }
    if (!role) return showErr("userFormErr", "请选择一个角色");
    if (!editingUser || pwd) {
      if (!pwd) return showErr("userFormErr", "请设置密码（" + (p.hint || "") + "）");
      if (pwd !== pwd2) return showErr("userFormErr", "两次输入的密码不一致");
      if (pwd.length < (p.min_len || 4)) return showErr("userFormErr", "密码至少 " + p.min_len + " 位");
    }

    var body = {
      display_name: display,
      role: role,
      enabled: enabled,
      expires_at: exp || null
    };
    if (pwd) body.password = pwd;

    var btn = this;
    btn.disabled = true;
    var req = editingUser
      ? api("/api/users/" + editingUser.id, { method: "PUT", body: body })
      : api("/api/users", {
          method: "POST",
          body: {
            username: username,
            password: pwd,
            display_name: display,
            role: role,
            enabled: enabled,
            expires_at: exp || null
          }
        });

    req.then(function () {
      toast(editingUser ? "已保存修改" : "账号已创建", "success");
      closeModal();
      return loadUsers();
    }).catch(function (e) {
      showErr("userFormErr", e.message);
    }).then(function () {
      btn.disabled = false;
    });
  });

  /* ---------------------------------------------------------- 改密弹窗 */
  function openPwdModal(u, forced) {
    STATE.pwdTarget = u;
    STATE.forced = !!forced;
    showErr("pwdFormErr", "");
    var isSelf = STATE.me && u.id === STATE.me.id;
    var dft = (STATE.policy || {}).default_password || "Aa123456";
    // 管理员重置他人密码：预填默认密码；本人改密 / 强制改密：留空自己输
    var preset = !isSelf && !forced ? dft : "";
    $("pfOld").value = "";
    $("pfNew").value = preset;
    $("pfNew2").value = preset;
    updateMeter("pfNew", "pfMeter");

    $("pwdModalTitle").textContent = forced ? "请修改初始密码" : isSelf ? "修改我的密码" : "重置密码";
    $("pwdLead").innerHTML = forced
      ? "为安全起见，首次登录必须修改初始密码。"
      : isSelf
        ? "修改后，其他设备上的登录会话会立即失效。"
        : "为 <b>" + esc(u.display_name || u.username) + "</b> 设置新密码";
    $("oldPwdField").classList.toggle("hidden", !isSelf);
    $("pfHint").textContent = (STATE.policy || {}).hint || "";
    $("pwdClose").classList.toggle("hidden", !!forced);
    $("pwdCancel").classList.toggle("hidden", !!forced);
    openModal("modalPwd", "pfOld");
  }

  $("pfSubmit").addEventListener("click", function () {
    showErr("pwdFormErr", "");
    var u = STATE.pwdTarget;
    if (!u) return;
    var isSelf = STATE.me && u.id === STATE.me.id;
    var oldPwd = $("pfOld").value;
    var pwd = $("pfNew").value;
    var pwd2 = $("pfNew2").value;
    var p = STATE.policy || {};

    if (isSelf && !oldPwd) return showErr("pwdFormErr", "请输入当前密码");
    if (!pwd) return showErr("pwdFormErr", "请输入新密码");
    if (pwd.length < (p.min_len || 4)) return showErr("pwdFormErr", "密码至少 " + p.min_len + " 位");
    if (pwd !== pwd2) return showErr("pwdFormErr", "两次输入的新密码不一致");

    var btn = this;
    btn.disabled = true;
    var req = isSelf
      ? api("/api/password", { method: "POST", body: { old_password: oldPwd, new_password: pwd } })
      : api("/api/users/" + u.id, { method: "PUT", body: { password: pwd } });

    req.then(function (d) {
      if (d && d.token) {
        STATE.token = d.token;
        localStorage.setItem("um_token", d.token);
      }
      if (d && d.user) STATE.me = d.user;
      var wasForced = STATE.forced;
      STATE.forced = false;
      closeModal();
      toast("密码已更新", "success");
      if (wasForced) enterApp();
      else if (STATE.view === "profile") loadProfile();
      else loadUsers();
    }).catch(function (e) {
      showErr("pwdFormErr", e.message);
    }).then(function () {
      btn.disabled = false;
    });
  });

  /* ---------------------------------------------------------- 其他操作 */
  function unlockUser(u) {
    api("/api/users/" + u.id + "/unlock", { method: "POST" })
      .then(function () {
        toast("已解除锁定", "success");
        return loadUsers();
      })
      .catch(function (e) { toast(e.message, "error"); });
  }

  function kickUser(u) {
    confirmBox(
      "强制下线",
      "强制「" + (u.display_name || u.username) + "」下线？该账号已登录的所有设备都需要重新登录。",
      "确认下线"
    ).then(function (ok) {
      if (!ok) return;
      api("/api/users/" + u.id + "/kick", { method: "POST" })
        .then(function () {
          toast("已强制下线", "success");
          return loadUsers();
        })
        .catch(function (e) { toast(e.message, "error"); });
    });
  }

  function deleteUser(u) {
    confirmBox(
      "删除账号",
      "删除「" + (u.display_name || u.username) + "」后该账号立即失效。账号本身不可恢复，但审计记录会永久保留。",
      "确认删除",
      true
    ).then(function (ok) {
      if (!ok) return;
      api("/api/users/" + u.id, { method: "DELETE" })
        .then(function () {
          toast("账号已删除", "success");
          return loadUsers();
        })
        .catch(function (e) { toast(e.message, "error"); });
    });
  }

  /* ---------------------------------------------------------- 导出 */
  $("btnExport").addEventListener("click", function () {
    var btn = this;
    btn.disabled = true;
    fetch("/api/users/export", { headers: { Authorization: "Bearer " + STATE.token } })
      .then(function (resp) {
        if (!resp.ok) throw new Error("导出失败");
        return resp.blob();
      })
      .then(function (blob) {
        var a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = "users_" + todayStr().replace(/-/g, "") + ".csv";
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(function () { URL.revokeObjectURL(a.href); }, 3000);
        toast("已导出 CSV", "success");
      })
      .catch(function (e) { toast(e.message, "error"); })
      .then(function () { btn.disabled = false; });
  });

  /* ---------------------------------------------------------- 批量导入 */
  function openImport() {
    STATE.importRows = [];
    $("importPreview").classList.add("hidden");
    $("importResult").classList.add("hidden");
    $("importResult").innerHTML = "";
    $("previewRows").innerHTML = "";
    $("fileInput").value = "";
    showErr("importErr", "");
    $("importConfirm").disabled = true;
    $("importConfirm").textContent = "开始导入";
    openModal("modalImport");
  }
  $("btnImport").addEventListener("click", openImport);

  $("pickFile").addEventListener("click", function () { $("fileInput").click(); });
  $("fileInput").addEventListener("change", function () {
    if (this.files && this.files[0]) readCsvFile(this.files[0]);
  });

  var dz = $("dropzone");
  ["dragenter", "dragover"].forEach(function (ev) {
    dz.addEventListener(ev, function (e) { e.preventDefault(); dz.classList.add("drag"); });
  });
  ["dragleave", "drop"].forEach(function (ev) {
    dz.addEventListener(ev, function (e) { e.preventDefault(); dz.classList.remove("drag"); });
  });
  dz.addEventListener("drop", function (e) {
    var f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
    if (f) readCsvFile(f);
  });

  function readCsvFile(file) {
    if (!/\.csv$/i.test(file.name)) {
      showErr("importErr", "请选择 .csv 文件（Excel 请另存为 CSV）");
      return;
    }
    var reader = new FileReader();
    reader.onload = function () { parseCsv(String(reader.result || "")); };
    reader.readAsText(file, "utf-8");
  }

  function parseCsvLine(line) {
    var out = [], cur = "", q = false;
    for (var i = 0; i < line.length; i++) {
      var c = line[i];
      if (q) {
        if (c === '"') {
          if (line[i + 1] === '"') { cur += '"'; i++; }
          else q = false;
        } else cur += c;
      } else if (c === '"') q = true;
      else if (c === ",") { out.push(cur); cur = ""; }
      else cur += c;
    }
    out.push(cur);
    return out;
  }

  function parseCsv(text) {
    text = text.replace(/^\ufeff/, "");
    var lines = text.split(/\r\n|\n|\r/).filter(function (l) { return l.trim() !== ""; });
    if (!lines.length) { showErr("importErr", "文件是空的"); return; }
    var head = parseCsvLine(lines[0]).map(function (h) { return h.trim(); });
    var hasHeader = /账号|username|密码|password/i.test(lines[0]);
    var start = hasHeader ? 1 : 0;
    if (hasHeader) {
      // 允许列顺序变化：按表头定位
      head = head.map(function (h) { return h.replace(/\s/g, ""); });
    }
    var rows = [];
    for (var i = start; i < lines.length; i++) {
      var c = parseCsvLine(lines[i]);
      var row = { row: i + 1, username: "", password: "", display_name: "", role: "", expires_at: "" };
      if (hasHeader) {
        head.forEach(function (h, idx) {
          var v = (c[idx] || "").trim();
          if (/^(登录账号|账号|username|account)$/i.test(h)) row.username = v;
          else if (/^(密码|password|pwd)$/i.test(h)) row.password = v;
          else if (/^(显示名|姓名|display_name|name)$/i.test(h)) row.display_name = v;
          else if (/^(角色|role)$/i.test(h)) row.role = v;
          else if (/^(有效期|expires_at|expiry)$/i.test(h)) row.expires_at = v;
        });
      } else {
        row.username = (c[0] || "").trim();
        row.password = (c[1] || "").trim();
        row.display_name = (c[2] || "").trim();
        row.role = (c[3] || "").trim();
        row.expires_at = (c[4] || "").trim();
      }
      rows.push(row);
    }
    if (rows.length > 500) {
      showErr("importErr", "单次最多导入 500 行，当前 " + rows.length + " 行，请拆分后再导入");
      return;
    }
    rows.forEach(validateRow);
    STATE.importRows = rows;
    renderPreview();
  }

  function validateRow(r) {
    var errs = [];
    var p = STATE.policy || { min_len: 4, classes: "none" };
    r.role = (r.role || "viewer").toLowerCase().trim();
    if (r.role === "管理员") r.role = "admin";
    if (r.role === "操作员") r.role = "operator";
    if (r.role === "浏览者" || r.role === "查看者") r.role = "viewer";
    if (!/^[A-Za-z0-9_.\-]{2,32}$/.test(r.username)) errs.push("账号格式不合法");
    // 密码留空不算错：后端按默认初始密码发放，并强制首次登录修改
    if (r.password && r.password.length < (p.min_len || 4)) errs.push("密码至少 " + (p.min_len || 4) + " 位");
    else if (r.password && p.classes === "letter_digit" && !(/[A-Za-z]/.test(r.password) && /[0-9]/.test(r.password)))
      errs.push("需字母+数字");
    else if (r.password && p.classes === "all4" && !(/[a-z]/.test(r.password) && /[A-Z]/.test(r.password) && /[0-9]/.test(r.password) && /[^A-Za-z0-9]/.test(r.password)))
      errs.push("需大小写+数字+符号");
    if (["admin", "operator", "viewer"].indexOf(r.role) < 0) errs.push("角色不合法");
    if (r.expires_at && !/^\d{4}-\d{2}-\d{2}$/.test(r.expires_at)) errs.push("有效期格式 YYYY-MM-DD");
    r.errors = errs;
    r.ok = errs.length === 0;
    return r;
  }

  function renderPreview() {
    var rows = STATE.importRows;
    var bad = rows.filter(function (r) { return !r.ok; }).length;
    $("importPreview").classList.remove("hidden");
    $("previewSummary").textContent = "共 " + rows.length + " 行 · 可导入 " + (rows.length - bad) + " 行" +
      (bad ? " · " + bad + " 行有问题" : "");
    $("previewRows").innerHTML = rows.map(function (r) {
      return (
        '<tr class="' + (r.ok ? "" : "bad-row") + '">' +
          '<td class="c-id">' + r.row + "</td>" +
          "<td>" + (esc(r.username) || '<span class="muted">—</span>') + "</td>" +
          "<td>" + (esc(r.display_name) || '<span class="muted">—</span>') + "</td>" +
          '<td><span class="pill ' + esc(r.role) + '">' + esc(r.role) + "</span></td>" +
          '<td class="time-cell">' + (esc(r.expires_at) || "—") + "</td>" +
          "<td>" + (r.ok ? '<span class="ok-text">通过</span>' : '<span class="err-text">' + esc(r.errors.join("；")) + "</span>") + "</td>" +
        "</tr>"
      );
    }).join("");
    $("importConfirm").disabled = rows.length === 0;
  }

  $("btnTemplate").addEventListener("click", function () {
    var p = STATE.policy || {};
    var dft = p.default_password || "Aa123456";
    var head = "登录账号,密码,显示名,角色,有效期\n";
    var sample = "zhangsan," + dft + ",张三,operator,\n";
    var blob = new Blob(["\ufeff" + head + sample], { type: "text/csv;charset=utf-8" });
    var a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "用户导入模板.csv";
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(function () { URL.revokeObjectURL(a.href); }, 2000);
    toast("模板已下载（密码可留空，默认发 " + dft + "）", "success");
  });

  $("importConfirm").addEventListener("click", function () {
    var btn = this;
    showErr("importErr", "");
    var good = STATE.importRows.filter(function (r) { return r.ok; });
    var localBad = STATE.importRows.filter(function (r) { return !r.ok; });
    if (!good.length) {
      showErr("importErr", "没有可导入的行");
      return;
    }
    btn.disabled = true;
    btn.textContent = "导入中…";
    api("/api/users/import", {
      method: "POST",
      body: {
        rows: good.map(function (r) {
          return {
            username: r.username,
            password: r.password,
            display_name: r.display_name,
            role: r.role,
            expires_at: r.expires_at || null
          };
        })
      }
    }).then(function (d) {
      var failed = (d.failed || []).slice();
      localBad.forEach(function (r) {
        failed.push({ row: r.row, username: r.username, error: "前端校验未通过：" + r.errors.join("；") });
      });
      failed.sort(function (a, b) { return a.row - b.row; });
      renderImportResult(d.created || [], failed);
      $("importConfirm").textContent = "完成";
      $("importConfirm").disabled = true;
      loadUsers();
    }).catch(function (e) {
      showErr("importErr", e.message);
      btn.disabled = false;
      btn.textContent = "开始导入";
    });
  });

  function renderImportResult(created, failed) {
    var box = $("importResult");
    box.classList.remove("hidden");
    var html = '<div class="import-result-box"><header>导入结果：成功 ' + created.length + " 条" +
      (failed.length ? "，失败 " + failed.length + " 条" : "，全部成功") + "</header>";
    if (failed.length) {
      html += "<ul>" + failed.map(function (f) {
        return "<li>第 " + f.row + " 行" + (f.username ? "（" + esc(f.username) + "）" : "") + "：" + esc(f.error) + "</li>";
      }).join("") + "</ul>";
    }
    html += "</div>";
    box.innerHTML = html;
  }

  /* ---------------------------------------------------------- 审计日志 */
  var AUDIT = { page: 0, size: 50, total: 0 };

  function openAudit() {
    openModal("modalAudit");
    loadAudit(true);
  }
  $("btnAudit").addEventListener("click", openAudit);
  $("auditRefresh").addEventListener("click", function () { loadAudit(true); });
  $("auditAction").addEventListener("change", function () { loadAudit(true); });
  $("auditStart").addEventListener("change", function () { loadAudit(true); });
  $("auditEnd").addEventListener("change", function () { loadAudit(true); });
  $("auditTarget").addEventListener("keydown", function (e) {
    if (e.key === "Enter") { e.preventDefault(); loadAudit(true); }
  });
  $("auditReset").addEventListener("click", function () {
    $("auditAction").value = "";
    $("auditTarget").value = "";
    $("auditStart").value = "";
    $("auditEnd").value = "";
    loadAudit(true);
  });
  $("auditPrev").addEventListener("click", function () {
    if (AUDIT.page > 0) { AUDIT.page--; loadAudit(false); }
  });
  $("auditNext").addEventListener("click", function () {
    var pages = Math.max(1, Math.ceil(AUDIT.total / AUDIT.size));
    if (AUDIT.page < pages - 1) { AUDIT.page++; loadAudit(false); }
  });

  function auditFilters() {
    var parts = [];
    var a = $("auditAction").value;
    var t = $("auditTarget").value.trim();
    var s = $("auditStart").value;
    var e = $("auditEnd").value;
    if (a) parts.push("action=" + encodeURIComponent(a));
    if (t) parts.push("target=" + encodeURIComponent(t));
    if (s) parts.push("start=" + encodeURIComponent(s));
    if (e) parts.push("end=" + encodeURIComponent(e));
    return parts.join("&");
  }

  function renderAuditPager() {
    var pages = Math.max(1, Math.ceil(AUDIT.total / AUDIT.size));
    $("auditPageInfo").textContent = AUDIT.page + 1 + " / " + pages;
    $("auditTotal").textContent = "共 " + AUDIT.total + " 条" +
      (auditFilters() ? "（已筛选）" : "");
    $("auditPrev").disabled = AUDIT.page <= 0;
    $("auditNext").disabled = AUDIT.page >= pages - 1;
  }

  function loadAudit(reset) {
    if (reset) AUDIT.page = 0;
    var f = auditFilters();
    var qs = "?limit=" + AUDIT.size + "&offset=" + AUDIT.page * AUDIT.size + (f ? "&" + f : "");
    $("auditRows").innerHTML = '<tr><td colspan="6" class="muted" style="padding:22px">加载中…</td></tr>';
    api("/api/users/audit" + qs).then(function (d) {
      var rows = d.audit || [];
      AUDIT.total = d.total || 0;
      $("auditEmpty").classList.toggle("hidden", rows.length > 0);
      $("auditRows").innerHTML = rows.map(function (r) {
        var a = ACTIONS[r.action] || { label: r.action, cls: "" };
        return (
          "<tr>" +
            '<td class="time-cell">' + esc((r.at || "").slice(0, 16)) + "</td>" +
            "<td>" + esc(r.actor || "系统") + "</td>" +
            '<td><span class="act-tag ' + a.cls + '">' + esc(a.label) + "</span></td>" +
            '<td class="mono">' + esc(r.target || "—") + "</td>" +
            "<td>" + diffHtml(r) + "</td>" +
            '<td class="mono">' + esc(r.ip || "—") + "</td>" +
          "</tr>"
        );
      }).join("");
      renderAuditPager();
    }).catch(function (e) {
      $("auditRows").innerHTML = '<tr><td colspan="6" class="err-text" style="padding:18px">' + esc(e.message) + "</td></tr>";
      $("auditEmpty").classList.add("hidden");
    });
  }

  $("auditExport").addEventListener("click", function () {
    var btn = this;
    btn.disabled = true;
    var f = auditFilters();
    fetch("/api/users/audit/export" + (f ? "?" + f : ""), {
      headers: { Authorization: "Bearer " + STATE.token }
    })
      .then(function (resp) {
        if (!resp.ok) throw new Error("导出失败（HTTP " + resp.status + "）");
        return resp.blob();
      })
      .then(function (blob) {
        var a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = "audit_" + todayStr().replace(/-/g, "") + ".csv";
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(function () { URL.revokeObjectURL(a.href); }, 3000);
        toast("审计日志已导出（本次导出已留痕）", "success");
        loadAudit(true);
      })
      .catch(function (e) { toast(e.message, "error"); })
      .then(function () { btn.disabled = false; });
  });

  function fmtVal(key, v) {
    if (key === "enabled") return v ? "启用" : "禁用";
    if (key === "role") {
      var m = { admin: "管理员", operator: "操作员", viewer: "浏览者" };
      return m[v] || v;
    }
    if (key === "expires_at") return v || "永不过期";
    if (key === "locked_until") return v || "未锁定";
    if (v === "" || v == null) return "—";
    if (typeof v === "object") return JSON.stringify(v);
    return String(v);
  }

  function diffHtml(r) {
    var oldV = r.old, newV = r.new;
    if (!oldV && newV) {
      if (newV.created) return '<span class="diff-plain">新增 ' + newV.created.length + " 个账号：" + esc(newV.created.join("、")) + "</span>";
      if (newV.exported !== undefined) return '<span class="diff-plain">导出 ' + newV.exported + " 条记录</span>";
      var parts = [];
      ["role", "enabled", "expires_at"].forEach(function (k) {
        if (newV[k] !== undefined) parts.push(FIELD_LABEL[k] + " " + fmtVal(k, newV[k]));
      });
      return '<span class="diff-plain">初始：' + esc(parts.join(" · ") || "—") + "</span>";
    }
    if (oldV && !newV) {
      var p2 = [];
      ["role", "enabled", "expires_at"].forEach(function (k) {
        if (oldV[k] !== undefined) p2.push(FIELD_LABEL[k] + " " + fmtVal(k, oldV[k]));
      });
      return '<span class="diff-plain">删除时：' + esc(p2.join(" · ") || "—") + "</span>";
    }
    if (!oldV && !newV) return '<span class="muted">' + esc(r.note || "—") + "</span>";

    var keys = Object.keys(newV);
    var lines = [];
    keys.forEach(function (k) {
      var a = oldV[k], b = newV[k];
      if (JSON.stringify(a) === JSON.stringify(b)) return;
      if (k === "password") {
        lines.push('<span class="diff-plain">密码已重置（明文不记录）</span>');
        return;
      }
      if (k === "exported") {
        lines.push('<span class="diff-plain">导出 ' + esc(String(b)) + " 条账号</span>");
        return;
      }
      lines.push(
        '<div class="diff-row"><span class="diff-key">' + FIELD_LABEL[k] + "：" +
        '</span><span class="diff-old">' + esc(fmtVal(k, a)) + "</span>" +
        '<span class="diff-arrow">→</span>' +
        '<span class="diff-new">' + esc(fmtVal(k, b)) + "</span></div>"
      );
    });
    if (!lines.length) return '<span class="muted">' + esc(r.note || "无字段变化") + "</span>";
    return '<div class="diff">' + lines.join("") + "</div>";
  }

  /* ---------------------------------------------------------- 个人中心 */
  function loadProfile() {
    api("/api/me").then(function (d) {
      STATE.me = d.user;
      STATE.policy = d.policy;
      renderMe();
      var u = d.user;
      $("profAvatar").textContent = initial(u);
      $("profAvatar").className = "avatar lg role-" + u.role;
      $("profName").textContent = u.display_name || u.username;
      $("profLogin").textContent = "@" + u.username;
      $("profRolePill").innerHTML = '<span class="pill ' + esc(u.role) + '">' + esc(u.role_label) + "</span>";
      $("profState").textContent = u.state_text || "—";
      $("profLastLogin").textContent = fmtTime(u.last_login_at) || "从未登录";
      $("profExpires").textContent = u.expires_at ? u.expires_at.slice(0, 10) : "永不过期";
      $("profCreated").textContent = (u.created_at || "").slice(0, 10) || "—";
      $("profLoginInput").value = u.username;
      $("profDisplayInput").value = u.display_name || "";
      $("profPwdHint").textContent = (d.policy && d.policy.hint) || "";
      loadMyAudit();
    }).catch(function (e) { toast(e.message, "error"); });
  }

  function loadMyAudit() {
    api("/api/me/audit?limit=50").then(function (d) {
      var rows = d.audit || [];
      if (!rows.length) {
        $("profAuditRows").innerHTML = '<tr><td colspan="4" class="muted" style="padding:18px">还没有记录</td></tr>';
        return;
      }
      $("profAuditRows").innerHTML = rows.map(function (r) {
        var a = ACTIONS[r.action] || { label: r.action, cls: "" };
        var diff = diffHtml(r).replace(/^<div class="diff">/, "").replace(/<\/div>$/, "");
        return (
          "<tr>" +
            '<td class="time-cell">' + esc((r.at || "").slice(0, 16)) + "</td>" +
            '<td><span class="act-tag ' + a.cls + '">' + esc(a.label) + "</span></td>" +
            "<td>" + diff + "</td>" +
            '<td class="mono">' + esc(r.ip || "—") + "</td>" +
          "</tr>"
        );
      }).join("");
    }).catch(function (e) {
      $("profAuditRows").innerHTML =
        '<tr><td colspan="4" class="err-text" style="padding:16px">' + esc(e.message) + "</td></tr>";
    });
  }

  $("profSaveProfile").addEventListener("click", function () {
    showErr("profProfileErr", "");
    api("/api/me", { method: "PUT", body: { display_name: $("profDisplayInput").value.trim() } })
      .then(function (d) {
        STATE.me = d.user;
        toast("资料已保存", "success");
        loadProfile();
      })
      .catch(function (e) { showErr("profProfileErr", e.message); });
  });

  $("profSavePwd").addEventListener("click", function () {
    showErr("profPwdErr", "");
    var oldPwd = $("meOld").value;
    var pwd = $("meNew").value;
    var pwd2 = $("meNew2").value;
    var p = STATE.policy || {};
    if (!oldPwd) return showErr("profPwdErr", "请输入当前密码");
    if (!pwd) return showErr("profPwdErr", "请输入新密码");
    if (pwd.length < (p.min_len || 4)) return showErr("profPwdErr", "密码至少 " + p.min_len + " 位");
    if (pwd !== pwd2) return showErr("profPwdErr", "两次输入的新密码不一致");
    var btn = this;
    btn.disabled = true;
    api("/api/password", { method: "POST", body: { old_password: oldPwd, new_password: pwd } })
      .then(function (d) {
        if (d.token) {
          STATE.token = d.token;
          localStorage.setItem("um_token", d.token);
        }
        if (d.user) STATE.me = d.user;
        $("meOld").value = "";
        $("meNew").value = "";
        $("meNew2").value = "";
        $("meMeter").style.width = "0%";
        toast("密码已更新，其他设备已下线", "success");
        loadProfile();
      })
      .catch(function (e) { showErr("profPwdErr", e.message); })
      .then(function () { btn.disabled = false; });
  });

  /* ---------------------------------------------------------- 弹窗通用 */
  function openModal(id, focusId) {
    var m = $(id);
    m.classList.add("open");
    m.setAttribute("aria-hidden", "false");
    setTimeout(function () {
      if (focusId && $(focusId)) $(focusId).focus();
    }, 40);
  }

  function closeModal() {
    if (STATE.forced && $("modalPwd").classList.contains("open")) {
      toast("必须先修改初始密码", "error");
      return;
    }
    Array.prototype.forEach.call(document.querySelectorAll(".modal.open"), function (m) {
      m.classList.remove("open");
      m.setAttribute("aria-hidden", "true");
    });
  }

  Array.prototype.forEach.call(document.querySelectorAll(".modal"), function (m) {
    m.addEventListener("click", function (ev) {
      if (ev.target === m) closeModal();
    });
    Array.prototype.forEach.call(m.querySelectorAll("[data-close]"), function (b) {
      b.addEventListener("click", closeModal);
    });
  });

  document.addEventListener("keydown", function (ev) {
    if (ev.key === "Escape") {
      var open = document.querySelector(".modal.open");
      if (open) { ev.preventDefault(); closeModal(); }
      return;
    }
    if (ev.key === "Enter") {
      var m = document.querySelector(".modal.open");
      if (!m) return;
      if (m.id === "modalUser" && ev.target.tagName === "INPUT") {
        ev.preventDefault();
        $("ufSubmit").click();
      } else if (m.id === "modalPwd" && ev.target.tagName === "INPUT") {
        ev.preventDefault();
        $("pfSubmit").click();
      }
    }
  });

  /* ---------------------------------------------------------- 显示密码 */
  document.addEventListener("click", function (ev) {
    var btn = ev.target.closest("[data-eye]");
    if (!btn) return;
    var input = $(btn.dataset.eye);
    if (!input) return;
    var show = input.type === "password";
    input.type = show ? "text" : "password";
    btn.textContent = show ? "隐藏" : "显示";
  });

  /* ---------------------------------------------------------- 启动 */
  function boot() {
    if (!STATE.token) return;
    api("/api/me").then(function (d) {
      STATE.me = d.user;
      STATE.policy = d.policy;
      enterApp();
      if (d.user && d.user.must_change_pwd) openPwdModal(d.user, true);
    }).catch(function () {
      logoutLocal(true);
    });
  }

  boot();
})();
