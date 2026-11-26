(() => {
  const $ = (id) => document.getElementById(id);

  let state = {
    session: {},
    config: {},
    adapters: [],
    proxyEnv: {},
    doctor: null,
    logs: [],
    wires: [],
    meta: {},
  };
  let toastTimer = null;
  let accountPeek = false;
  let logRenderRAF = 0;
  let mainLogsDirty = false;
  let drawerLogsDirty = false;
  let pendingOnlineConfigSync = false;

  const PRIVACY_KEEP_IPS = new Set([
    "127.0.0.1", "0.0.0.0", "27.159.75.27", "223.5.5.5", "114.114.114.114", "119.29.29.29",
    "8.8.8.8", "1.1.1.1", "202.96.128.86", "202.96.128.166", "202.96.134.133", "202.96.128.68",
    "125.88.59.131", "61.140.12.23",
  ]);

  function isPrivacyMode() {
    return !state.config || state.config.privacyMode !== false;
  }

  function escapeRegex(s) {
    return String(s).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }

  function maskPrivacyIPv4(ip) {
    if (PRIVACY_KEEP_IPS.has(ip)) return ip;
    const p = ip.split(".").map(Number);
    if (p.length !== 4 || p.some((x) => Number.isNaN(x) || x < 0 || x > 255)) return ip;
    if (p[0] === 198 && (p[1] === 18 || p[1] === 19)) return "<Fake-IP>";
    if (p[0] === 10 || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) || (p[0] === 192 && p[1] === 168) || (p[0] === 169 && p[1] === 254)) {
      return "<内网IP已隐藏>";
    }
    return "<IP已隐藏>";
  }

  function maskPrivacyText(input) {
    const str = String(input ?? "");
    if (!str || !isPrivacyMode()) return str;
    let out = str;
    const acct = (($("inp-account") && $("inp-account").value) || (state.config && state.config.account) || "").trim();
    if (acct.length >= 3) {
      out = out.split(acct).join("***");
    }
    out = out.replace(/\b1[3-9]\d{9}\b/g, "<手机号已隐藏>");
    out = out.replace(/\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b/g, "<MAC已隐藏>");
    out = out.replace(/\[[0-9a-fA-F]{8,}\]/g, "[<已隐藏>]");
    out = out.replace(/\b(wlanuserip|wlanacip|wlanacname|userip|nasip|acip|basip)=([^&\s"')]+)/gi, "$1=<IP已隐藏>");
    out = out.replace(/\b(schoolid|school_id|school|cdc-schoolid)(\s*[:=]\s*)([^\s&,)"']+)/gi, "$1$2<已隐藏>");
    out = out.replace(/(学校(?:\s*ID)?)(\s*[:=：]\s*)([^\s&,)"']+)/g, "$1$2<已隐藏>");
    out = out.replace(/\b(domain|cdc-domain)(\s*[:=]\s*)([^\s&,)"']+)/gi, "$1$2<已隐藏>");
    out = out.replace(/(域名)(\s*[:=：]\s*)([^\s&,)"']+)/g, "$1$2<已隐藏>");
    out = out.replace(/\b(areacode|area|cdc-area)(\s*[:=]\s*)([^\s&,)"']+)/gi, "$1$2<已隐藏>");
    out = out.replace(/(区号|地区)(\s*[:=：]\s*)([^\s&,)"']+)/g, "$1$2<已隐藏>");
    const sess = state.session || {};
    if (sess.domain && sess.domain.length >= 2) {
      const dmRe = new RegExp(`(^|[^a-z0-9_])${escapeRegex(sess.domain)}([^a-z0-9_]|$)`, "gi");
      out = out.replace(dmRe, "$1<已隐藏>$2");
    }
    if (sess.area && sess.area.length >= 3) {
      const arRe = new RegExp(`(^|[^0-9])${escapeRegex(sess.area)}([^0-9]|$)`, "g");
      out = out.replace(arRe, "$1<已隐藏>$2");
    }
    out = out.replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, (m) => maskPrivacyIPv4(m));
    return out;
  }

  function applyPrivacyUI() {
    const priv = isPrivacyMode();
    const acctInp = $("inp-account");
    if (acctInp) {
      acctInp.type = priv && !accountPeek ? "password" : "text";
    }
    const sw = $("set-privacy-mode");
    if (sw) sw.checked = priv;
    const sb = $("sb-privacy-btn");
    if (sb) sb.textContent = priv ? "隐私保护: 开" : "隐私保护: 关";
  }

  async function setPrivacyMode(enabled) {
    state.config = { ...(state.config || {}), privacyMode: !!enabled };
    if (enabled) accountPeek = false;
    applyPrivacyUI();
    renderSession();
    renderAdapters();
    if (state.doctor) renderDoctor(state.doctor);
    mainLogsDirty = true;
    drawerLogsDirty = true;
    flushLogsRender(true);
    renderWires();
    try {
      await api("/api/settings", { method: "POST", body: JSON.stringify({ privacyMode: !!enabled }) });
    } catch (_) {}
  }

  function showToast(msg) {
    const el = $("toast");
    el.textContent = msg;
    el.classList.remove("hidden");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.add("hidden"), 2600);
  }

  async function api(path, opts = {}) {
    const res = await fetch(path, {
      headers: { "Content-Type": "application/json" },
      ...opts,
    });
    const text = await res.text();
    let data = {};
    try {
      data = text ? JSON.parse(text) : {};
    } catch (_) {
      data = { raw: text };
    }
    if (!res.ok) {
      throw new Error(data.error || `HTTP ${res.status}`);
    }
    return data;
  }

  // ---------- 主题切换 ----------
  function resolveTheme(mode) {
    if (mode === "system") {
      return window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches
        ? "light"
        : "dark";
    }
    return mode === "light" ? "light" : "dark";
  }

  function applyTheme(mode) {
    const eff = resolveTheme(mode);
    document.documentElement.setAttribute("data-theme", eff);
    $("set-theme").value = mode || "dark";
    $("sb-theme-btn").textContent = eff === "light" ? "亮色" : "暗色";
  }

  async function changeTheme(mode) {
    applyTheme(mode);
    try {
      await api("/api/settings", { method: "POST", body: JSON.stringify({ theme: mode }) });
    } catch (_) {}
  }

  // ---------- 导航与子标签 ----------
  function switchView(name) {
    document.querySelectorAll(".act-btn").forEach((b) => {
      b.classList.toggle("active", b.dataset.view === name);
    });
    document.querySelectorAll(".view").forEach((v) => {
      v.classList.toggle("active", v.id === `view-${name}`);
    });
    if (name === "network") {
      refreshAdapters();
    } else if (name === "debug") {
      flushLogsRender();
    }
  }

  function switchSubtab(name) {
    document.querySelectorAll(".subtab").forEach((b) => {
      b.classList.toggle("active", b.dataset.subtab === name);
    });
    document.querySelectorAll(".subpane").forEach((p) => {
      p.classList.toggle("active", p.id === `subpane-${name}`);
    });
    $("log-filters").style.visibility = name === "logs" ? "visible" : "hidden";
    if (name === "logs") {
      flushLogsRender();
    } else if (name === "issue") {
      refreshIssuePreview();
    }
  }

  // ---------- 渲染函数 ----------
  function stateLabel(st, stage) {
    if (st === "connected") return stage === "already-online" ? "已在线" : "已连接";
    if (st === "disconnecting") return "正在注销...";
    if (st === "connecting") {
      const map = {
        detect: "探测出口...",
        config: "识别学校...",
        negotiate: "协商算法...",
        ticket: "获取凭据...",
        login: "正在登录...",
        reconnect: "重连中...",
      };
      return map[stage] || "连接中...";
    }
    if (st === "error") return "认证失败";
    return "未连接";
  }

  function renderSession() {
    const s = state.session || {};
    const st = s.state || "disconnected";
    const lbl = stateLabel(st, s.stage);

    const badge = $("conn-badge");
    badge.dataset.state = st;
    badge.textContent = lbl;

    document.body.classList.toggle("connected", st === "connected");
    $("sb-dot").dataset.state = st;
    $("sb-state-text").textContent = lbl;

    const btnConn = $("btn-connect");
    const btnReconn = $("btn-reconnect");
    const btnDisc = $("btn-disconnect");
    btnConn.disabled = st === "connecting" || st === "disconnecting";
    btnConn.textContent = st === "connecting" ? "正在连接..." : st === "connected" ? "重新登录" : "连接校园网";
    if (btnReconn) btnReconn.disabled = st === "connecting" || st === "disconnecting";
    btnDisc.disabled = st === "disconnected" || st === "disconnecting";
    btnDisc.textContent = st === "disconnecting" ? "正在注销..." : "断开下线";

    // 错误栏
    const errBox = $("connect-error-box");
    if (s.lastError) {
      errBox.classList.remove("hidden");
      $("connect-error-msg").textContent = maskPrivacyText(s.lastError);
    } else {
      errBox.classList.add("hidden");
    }

    const priv = isPrivacyMode();
    // 遥测卡片
    $("tel-nic").textContent = s.nicName ? `${maskPrivacyText(s.nicName)} (#${s.nicIfIndex})` : "-";
    if (priv) {
      $("tel-ips").textContent = s.userIP || s.acIP ? "<内网IP已隐藏> / <AC已隐藏>" : "-";
    } else {
      $("tel-ips").textContent = s.userIP ? `${s.userIP} / ${s.acIP || "-"}` : "-";
    }
    const schoolStr = [s.school, s.domain, s.area].filter(Boolean).join(" / ");
    if (priv) {
      $("tel-school").textContent = schoolStr ? "已自动识别 (已隐藏)" : "-";
      $("auto-school-vals").textContent = schoolStr
        ? "学校 / 域名 / 区号：已识别 (隐私保护已隐藏)"
        : "将在检测认证时自动从各校网关获取";
    } else {
      $("tel-school").textContent = schoolStr || "-";
      $("auto-school-vals").textContent = schoolStr
        ? `学校 ID: ${s.school || "-"}  |  域名: ${s.domain || "-"}  |  区号: ${s.area || "-"}`
        : "将在检测认证时自动从各校网关获取";
    }
    $("school-source-tag").textContent = state.config.manualOverride ? "手动覆盖" : "自动获取";

    $("tel-algo").textContent = s.algoFamily
      ? `${s.algoFamily} (${(s.algoID || "").slice(0, 8)})`
      : s.algoID || "-";
    $("tel-keep").textContent = s.keepURL
      ? `${maskPrivacyText(s.keepURL)} (${s.keepRetry || 300}s)`
      : "-";
    $("tel-hb").textContent =
      s.helloCount > 0 ? `第 ${s.helloCount} 次 @ ${s.lastHeartbeat || "-"}` : "-";
    $("tel-bypass").textContent = s.bypassMode || (state.proxyEnv && state.proxyEnv.bypassMode) || "物理直连就绪";
    $("header-bypass-pill").textContent = s.nicName ? `${maskPrivacyText(s.nicName)} · TUN 绕过` : "自动物理直连";

    // 耗时条
    const tm = s.timings || {};
    const tot = tm.totalMs || 0;
    $("tel-total-ms").textContent = tot > 0 ? `总计 ${tot}ms` : "-";
    const fmtMs = (v) => (v ? `${v}ms` : "-");
    $("ms-detect").textContent = fmtMs(tm.detectMs);
    $("ms-config").textContent = fmtMs(tm.configMs);
    $("ms-neg").textContent = fmtMs(tm.negotiateMs);
    $("ms-ticket").textContent = fmtMs(tm.ticketMs);
    $("ms-login").textContent = fmtMs(tm.loginMs);

    const denom = Math.max(tot, 1);
    const pct = (v) => (tot > 0 && v > 0 ? `${Math.max(4, (v / denom) * 100).toFixed(1)}%` : "0%");
    $("tb-detect").style.width = pct(tm.detectMs);
    $("tb-config").style.width = pct(tm.configMs);
    $("tb-neg").style.width = pct(tm.negotiateMs);
    $("tb-ticket").style.width = pct(tm.ticketMs);
    $("tb-login").style.width = pct(tm.loginMs);

    // 多跳重定向
    const hops = s.redirectHops || [];
    $("hops-count").textContent = `${hops.length} 跳`;
    const hopsList = $("hops-list");
    if (hops.length === 0) {
      hopsList.innerHTML = `<div class="muted-empty">认证发起后将记录各校网关重定向轨迹</div>`;
    } else {
      hopsList.innerHTML = hops
        .map((h, idx) => {
          const schoolBadge =
            h.school || h.domain || h.area
              ? priv
                ? " → 学校参数已隐藏"
                : ` → school=${escapeHTML(h.school)} domain=${escapeHTML(h.domain)} area=${escapeHTML(h.area)}`
              : "";
          return `<div class="hop-item">${idx + 1}. [${h.status || 0} ${escapeHTML(h.kind)}] ${escapeHTML(
            maskPrivacyText(h.url)
          )} (${h.rttMs}ms)${schoolBadge}</div>`;
        })
        .join("");
    }

    // 状态栏
    $("sb-nic-text").textContent = s.nicName
      ? priv
        ? `${maskPrivacyText(s.nicName)} (IP已隐藏)`
        : `${s.nicName} (${s.userIP || ""})`
      : "出口: 自动物理网卡";
    const px = state.proxyEnv || {};
    $("sb-tun-badge").textContent = px.tunActive ? "TUN 已绕过" : "物理直连";
    $("sb-timing-text").textContent = tot > 0 ? `${tot}ms` : "";
    $("sb-algo-text").textContent = s.algoFamily || "";
    $("sb-hb-text").textContent = s.helloCount > 0 ? `心跳 ×${s.helloCount}` : "";
  }

  function updateSavedPasswordHint() {
    const c = state.config || {};
    const curAcct = (($("inp-account") && $("inp-account").value) || "").trim();
    const savedAcct = (c.account || "").trim();
    const sameSaved = !!(c.hasSavedPassword && savedAcct && curAcct === savedAcct);
    if (sameSaved) {
      $("saved-pwd-hint").textContent = "(已安全加密保存)";
      $("inp-password").placeholder = "已保存加密密码，留空直接连接";
    } else if (c.hasSavedPassword && curAcct && savedAcct && curAcct !== savedAcct) {
      $("saved-pwd-hint").textContent = "(已切换账号，请输入密码)";
      $("inp-password").placeholder = "输入新账号密码";
    } else {
      $("saved-pwd-hint").textContent = "";
      $("inp-password").placeholder = "输入密码";
    }
  }

  function renderConfig() {
    const c = state.config || {};
    if (!$("inp-account").value && c.account) {
      $("inp-account").value = c.account;
    }
    updateSavedPasswordHint();
    $("chk-remember").checked = c.rememberPassword !== false;
    $("chk-force").checked = !!c.forceReauth;
    $("chk-manual-school").checked = !!c.manualOverride;
    $("inp-school").value = c.school || "";
    $("inp-domain").value = c.domain || "";
    $("inp-area").value = c.area || "";
    toggleSchoolInputs(!!c.manualOverride);

    $("set-theme").value = c.theme || "dark";
    $("set-close-tray").checked = c.closeToTray !== false;
    $("set-auto-connect").checked = !!c.autoConnect;
    $("set-auto-start").checked = !!(state.meta && state.meta.autoStart);
    $("set-query-state").checked = !!c.queryState;
    $("set-debug-wire").checked = !!c.debugWire;
    $("chk-debug-wire").checked = !!c.debugWire;
    if (state.meta && state.meta.coreMode) {
      $("settings-meta-label").textContent = `core=${state.meta.coreMode}`;
    }
    applyTheme(c.theme || "dark");
    applyPrivacyUI();
  }

  function toggleSchoolInputs(enabled) {
    $("inp-school").disabled = !enabled;
    $("inp-domain").disabled = !enabled;
    $("inp-area").disabled = !enabled;
  }

  function renderAdapters() {
    const adapters = state.adapters || [];
    const px = state.proxyEnv || {};
    const pinned = (state.config && state.config.pinnedIfIndex) || 0;

    const tags = [];
    if (px.tunActive) tags.push(`检测到 TUN 网卡 (${(px.tunAdapters || []).join(", ") || "分流路由"})`);
    if (px.systemProxyOn) tags.push(`系统代理 (${px.systemProxyAddr || "开启"})`);
    if (px.envProxyVars && px.envProxyVars.length) tags.push(`代理环境变量 (${px.envProxyVars.length} 项)`);
    $("proxy-summary-bar").innerHTML = `
      <div><strong>绕过策略：</strong>${escapeHTML(px.bypassMode || "IP_UNICAST_IF 物理直连")}</div>
      <div class="badge ${px.tunActive || px.systemProxyOn ? "badge-ok" : "badge-muted"}">
        ${escapeHTML(tags.length ? tags.join(" · ") : "未检测到代理拦截")}
      </div>`;

    $("adapters-tbody").innerHTML = adapters
      .map((a) => {
        let cls = "badge-muted";
        if (a.isPhysical) cls = "badge-ok";
        else if (a.isTUN) cls = "badge-warn";
        const isPinned = pinned > 0 && pinned === a.ifIndex;
        const canPin = a.isUp && a.ip4 && !a.isTUN;
        return `<tr>
          <td><span class="badge ${a.isUp ? "badge-ok" : "badge-muted"}">${a.isUp ? "UP" : "DOWN"}</span></td>
          <td title="${escapeHTML(maskPrivacyText(a.description))}">${escapeHTML(maskPrivacyText(a.name))}</td>
          <td><span class="badge ${cls}">${escapeHTML(a.typeLabel)}${a.tunReason ? " · " + escapeHTML(a.tunReason) : ""}</span></td>
          <td class="mono">${escapeHTML(maskPrivacyText(a.ip4 || "-"))}</td>
          <td class="mono">${escapeHTML(maskPrivacyText(a.gateway || "-"))}</td>
          <td class="mono">${escapeHTML(maskPrivacyText((a.dnsServers || []).join(", ") || "-"))}</td>
          <td class="mono">${a.hasDefaultRoute ? `0/0 (m=${a.defaultMetric})` : "-"}</td>
          <td>
            <button type="button" class="btn btn-xs ${isPinned ? "btn-primary" : "btn-secondary"}"
              ${canPin ? "" : "disabled"} onclick="window.__pinIf(${a.ifIndex})">
              ${isPinned ? "已固定" : "设为主出口"}
            </button>
          </td>
        </tr>`;
      })
      .join("");
  }

  function renderDoctor(rep) {
    if (!rep) return;
    $("doctor-time").textContent = rep.generatedAt || "";
    $("doctor-list").innerHTML = (rep.checks || [])
      .map((c) => {
        const cls = c.status === "pass" ? "badge-ok" : c.status === "warn" ? "badge-warn" : "badge-err";
        const lbl = c.status === "pass" ? "PASS" : c.status === "warn" ? "WARN" : "FAIL";
        return `<div class="doctor-item">
          <div class="doctor-main">
            <div class="doctor-name">${escapeHTML(c.name)} ${c.rttMs ? `<span class="mono header-meta">(${c.rttMs}ms)</span>` : ""}</div>
            <div class="doctor-detail">${escapeHTML(maskPrivacyText(c.detail))}</div>
            ${c.advice ? `<div class="doctor-advice">建议: ${escapeHTML(maskPrivacyText(c.advice))}</div>` : ""}
          </div>
          <span class="badge ${cls}">${lbl}</span>
        </div>`;
      })
      .join("");
  }

  function isMainLogsVisible() {
    const view = $("view-debug");
    const pane = $("subpane-logs");
    return !!(view && view.classList.contains("active") && pane && pane.classList.contains("active"));
  }

  function isDrawerLogsVisible() {
    const drawer = $("output-drawer");
    return !!(drawer && !drawer.classList.contains("collapsed"));
  }

  function renderMainLogs(logs) {
    const lvl = $("sel-log-level").value;
    const kw = $("inp-log-search").value.trim().toLowerCase();

    const filtered = logs.filter((l) => {
      if (lvl !== "ALL" && l.level !== lvl) return false;
      if (kw && !`${l.stage} ${l.message}`.toLowerCase().includes(kw)) return false;
      return true;
    });

    const html = filtered
      .map(
        (l) =>
          `<div class="log-line log-${escapeHTML(l.level)}"><span class="log-time">${escapeHTML(
            l.time
          )}</span><span class="log-stage">[${escapeHTML(l.stage)}]</span>${escapeHTML(maskPrivacyText(l.message))}</div>`
      )
      .join("");

    const box = $("subpane-logs");
    box.innerHTML = html || `<div class="muted-empty">暂无匹配的日志记录</div>`;
    box.scrollTop = box.scrollHeight;
  }

  function renderDrawerLogs(logs) {
    const drawer = $("drawer-logs");
    const tail = logs.slice(-80);
    drawer.innerHTML =
      tail
        .map(
          (l) =>
            `<div class="log-line log-${escapeHTML(l.level)}"><span class="log-time">${escapeHTML(
              l.time
            )}</span><span class="log-stage">[${escapeHTML(l.stage)}]</span>${escapeHTML(maskPrivacyText(l.message))}</div>`
        )
        .join("") || `<div class="muted-empty">等待日志...</div>`;
    drawer.scrollTop = drawer.scrollHeight;
  }

  function flushLogsRender(force) {
    const logs = state.logs || [];
    $("cnt-logs").textContent = String(logs.length);
    if (isMainLogsVisible() && (force || mainLogsDirty)) {
      renderMainLogs(logs);
      mainLogsDirty = false;
    }
    if (isDrawerLogsVisible() && (force || drawerLogsDirty)) {
      renderDrawerLogs(logs);
      drawerLogsDirty = false;
    }
  }

  function scheduleLogsRender() {
    const logs = state.logs || [];
    $("cnt-logs").textContent = String(logs.length);
    mainLogsDirty = true;
    drawerLogsDirty = true;
    if (logRenderRAF) return;
    logRenderRAF = requestAnimationFrame(() => {
      logRenderRAF = 0;
      flushLogsRender(false);
    });
  }

  function renderLogs() {
    mainLogsDirty = true;
    drawerLogsDirty = true;
    flushLogsRender(true);
  }

  function renderWires() {
    const wires = state.wires || [];
    $("cnt-wires").textContent = String(wires.length);
    $("wires-tbody").innerHTML = wires
      .slice()
      .reverse()
      .map((w) => {
        const cls = w.error || w.status >= 500 ? "badge-err" : w.status === 200 ? "badge-ok" : "badge-warn";
        const dispURL = maskPrivacyText(shortURL(w.url));
        const dispMsg = maskPrivacyText(w.error || w.bodyPreview || "-");
        return `<tr>
          <td class="mono">${escapeHTML(w.time)}</td>
          <td class="mono" title="${escapeHTML(maskPrivacyText(w.url))}">${escapeHTML(dispURL)}</td>
          <td><span class="badge ${cls}">${w.status || "ERR"}</span></td>
          <td class="mono">${escapeHTML(w.errorCode || "-")}</td>
          <td class="mono">${w.rttMs}ms</td>
          <td class="mono">${w.reqBytes} / ${w.respBytes}B</td>
          <td class="mono">${escapeHTML(w.serverTag || "-")}</td>
          <td class="mono">${escapeHTML(dispMsg)}</td>
        </tr>`;
      })
      .join("");
  }

  function shortURL(u) {
    try {
      const p = new URL(u);
      return p.host + p.pathname;
    } catch (_) {
      return u;
    }
  }

  function escapeHTML(s) {
    return String(s ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  // ---------- 操作动作 ----------
  async function loadInitialState() {
    try {
      const [stData, metaData] = await Promise.all([api("/api/state"), api("/api/ui/meta")]);
      state = { ...state, ...stData, meta: metaData };
      renderConfig();
      renderSession();
      renderAdapters();
      if (state.doctor) renderDoctor(state.doctor);
      renderLogs();
      renderWires();
    } catch (e) {
      showToast("加载状态失败: " + e.message);
    }
  }

  async function triggerConnect(forceOverride) {
    const account = $("inp-account").value.trim();
    const password = $("inp-password").value;
    const rememberPassword = $("chk-remember").checked;
    const oneShotForce = forceOverride !== undefined;
    const force = oneShotForce ? !!forceOverride : $("chk-force").checked;
    const manualOverride = $("chk-manual-school").checked;
    const school = $("inp-school").value.trim();
    const domain = $("inp-domain").value.trim();
    const area = $("inp-area").value.trim();

    if (!account) {
      showToast("请先输入校园网账号");
      $("inp-account").focus();
      return;
    }
    const canUseSaved = !!(state.config && state.config.hasSavedPassword && account === (state.config.account || ""));
    if (!password && !canUseSaved) {
      showToast(state.config && state.config.hasSavedPassword ? "已切换账号，请输入新账号密码" : "请输入校园网密码");
      $("inp-password").focus();
      return;
    }

    try {
      pendingOnlineConfigSync = true;
      await api("/api/connect", {
        method: "POST",
        body: JSON.stringify({
          account,
          password,
          useSavedPassword: password === "" && canUseSaved,
          rememberPassword,
          force,
          oneShotForce,
          manualOverride,
          school,
          domain,
          area,
          pinnedIfIndex: (state.config && state.config.pinnedIfIndex) || 0,
          debugWire: $("set-debug-wire").checked,
          queryState: $("set-query-state").checked,
        }),
      });
      showToast("已发起认证");
    } catch (e) {
      pendingOnlineConfigSync = false;
      showToast(e.message);
    }
  }

  async function refreshAdapters() {
    try {
      const res = await api("/api/adapters");
      state.adapters = res.adapters || [];
      state.proxyEnv = res.proxyEnv || {};
      renderAdapters();
    } catch (e) {
      showToast("刷新网卡失败: " + e.message);
    }
  }

  window.__pinIf = async (ifIndex) => {
    try {
      const res = await api("/api/settings", {
        method: "POST",
        body: JSON.stringify({ pinnedIfIndex: ifIndex }),
      });
      state.config = res.config || state.config;
      renderAdapters();
      showToast(ifIndex === 0 ? "已恢复自动选择物理网卡" : `已固定物理出口 #${ifIndex}`);
    } catch (e) {
      showToast(e.message);
    }
  };

  async function runDoctor() {
    const btn = $("btn-run-doctor");
    btn.disabled = true;
    btn.textContent = "体检中...";
    try {
      const rep = await api("/api/doctor", { method: "POST" });
      state.doctor = rep;
      state.adapters = rep.adapters || state.adapters;
      state.proxyEnv = rep.proxyEnv || state.proxyEnv;
      renderAdapters();
      renderDoctor(rep);
      showToast("网络体检完成");
    } catch (e) {
      showToast("体检失败: " + e.message);
    } finally {
      btn.disabled = false;
      btn.textContent = "一键网络体检";
    }
  }

  async function fetchIssueReport() {
    const res = await api("/api/issue", { method: "POST" });
    $("issue-preview-text").textContent = res.markdown || "";
    return res;
  }

  async function refreshIssuePreview() {
    try {
      await fetchIssueReport();
    } catch (e) {
      showToast("生成报告失败: " + e.message);
    }
  }

  async function copyIssueReport() {
    try {
      const res = await fetchIssueReport();
      await navigator.clipboard.writeText(res.markdown || "");
      showToast("已复制脱敏 Issue Markdown 报告到剪贴板");
    } catch (e) {
      showToast("复制失败: " + e.message);
    }
  }

  async function exportIssueFile(kind) {
    try {
      const res = await fetchIssueReport();
      const name = kind === "json" ? res.jsonName : res.mdName;
      const content = kind === "json" ? res.json : res.markdown;
      const saved = await api("/api/ui/save-file", {
        method: "POST",
        body: JSON.stringify({ name, content }),
      });
      if (saved.ok && saved.path) {
        showToast("已导出到: " + saved.path);
      }
    } catch (e) {
      showToast("导出失败: " + e.message);
    }
  }

  function startSSE() {
    const es = new EventSource("/api/events");
    es.onmessage = (ev) => {
      try {
        const pkt = JSON.parse(ev.data);
        if (pkt.type === "state") {
          state.session = pkt.data || {};
          renderSession();
          if (pendingOnlineConfigSync && state.session.state === "connected" && state.session.stage === "online") {
            pendingOnlineConfigSync = false;
            api("/api/state")
              .then((stData) => {
                if (stData && stData.config) {
                  state.config = stData.config;
                  const curAcct = $("inp-account").value.trim();
                  if (stData.config.hasSavedPassword && curAcct === (stData.config.account || "")) {
                    $("inp-password").value = "";
                  }
                  renderConfig();
                }
              })
              .catch(() => {});
          } else if (state.session.state === "error" || state.session.state === "disconnected") {
            pendingOnlineConfigSync = false;
          }
        } else if (pkt.type === "log") {
          state.logs.push(pkt.data);
          if (state.logs.length > 500) state.logs.shift();
          scheduleLogsRender();
        } else if (pkt.type === "wire") {
          state.wires.push(pkt.data);
          if (state.wires.length > 60) state.wires.shift();
          renderWires();
        }
      } catch (_) {}
    };
    es.onerror = () => {
      setTimeout(() => {
        if (es.readyState === EventSource.CLOSED) startSSE();
      }, 2500);
    };
  }

  // ---------- 事件绑定 ----------
  document.querySelectorAll(".act-btn").forEach((b) => {
    b.addEventListener("click", () => switchView(b.dataset.view));
  });
  document.querySelectorAll(".subtab").forEach((b) => {
    b.addEventListener("click", () => switchSubtab(b.dataset.subtab));
  });

  $("login-form").addEventListener("submit", (e) => {
    e.preventDefault();
    triggerConnect();
  });
  $("btn-reconnect").addEventListener("click", () => triggerConnect(true));
  $("btn-disconnect").addEventListener("click", async () => {
    const btn = $("btn-disconnect");
    if (btn.disabled) return;
    btn.disabled = true;
    btn.textContent = "正在注销...";
    try {
      await api("/api/disconnect", { method: "POST" });
      showToast("已断开校园网连接");
    } catch (e) {
      showToast(e.message);
    } finally {
      renderSession();
    }
  });
  $("inp-account").addEventListener("input", updateSavedPasswordHint);
  $("btn-toggle-account").addEventListener("click", () => {
    accountPeek = !accountPeek;
    applyPrivacyUI();
  });
  $("btn-toggle-pwd").addEventListener("click", () => {
    const inp = $("inp-password");
    inp.type = inp.type === "password" ? "text" : "password";
  });
  $("chk-force").addEventListener("change", (e) => {
    state.config = { ...(state.config || {}), forceReauth: e.target.checked };
    api("/api/settings", { method: "POST", body: JSON.stringify({ forceReauth: e.target.checked }) });
  });
  $("chk-manual-school").addEventListener("change", (e) => {
    toggleSchoolInputs(e.target.checked);
  });
  $("btn-goto-issue").addEventListener("click", () => {
    switchView("debug");
    switchSubtab("issue");
  });

  $("btn-refresh-adapters").addEventListener("click", refreshAdapters);
  $("btn-run-doctor").addEventListener("click", runDoctor);
  $("btn-pin-auto").addEventListener("click", () => window.__pinIf(0));

  $("btn-copy-issue").addEventListener("click", copyIssueReport);
  $("btn-drawer-copy-issue").addEventListener("click", copyIssueReport);
  $("btn-regen-issue").addEventListener("click", refreshIssuePreview);
  $("btn-export-md").addEventListener("click", () => exportIssueFile("md"));
  $("btn-export-json").addEventListener("click", () => exportIssueFile("json"));

  const clearLogs = async () => {
    await api("/api/logs/clear", { method: "POST" });
    state.logs = [];
    state.wires = [];
    renderLogs();
    renderWires();
  };
  $("btn-clear-logs").addEventListener("click", clearLogs);
  $("btn-drawer-clear").addEventListener("click", clearLogs);

  $("sel-log-level").addEventListener("change", renderLogs);
  $("inp-log-search").addEventListener("input", renderLogs);

  const syncDebugFlag = async (checked) => {
    $("set-debug-wire").checked = checked;
    $("chk-debug-wire").checked = checked;
    await api("/api/settings", { method: "POST", body: JSON.stringify({ debugWire: checked }) });
  };
  $("chk-debug-wire").addEventListener("change", (e) => syncDebugFlag(e.target.checked));
  $("set-debug-wire").addEventListener("change", (e) => syncDebugFlag(e.target.checked));

  $("set-theme").addEventListener("change", (e) => changeTheme(e.target.value));
  $("sb-theme-btn").addEventListener("click", () => {
    const cur = document.documentElement.getAttribute("data-theme") || "dark";
    changeTheme(cur === "dark" ? "light" : "dark");
  });
  $("set-privacy-mode").addEventListener("change", (e) => setPrivacyMode(e.target.checked));
  $("sb-privacy-btn").addEventListener("click", () => setPrivacyMode(!isPrivacyMode()));

  $("set-close-tray").addEventListener("change", (e) =>
    api("/api/settings", { method: "POST", body: JSON.stringify({ closeToTray: e.target.checked }) })
  );
  $("set-auto-connect").addEventListener("change", (e) =>
    api("/api/settings", { method: "POST", body: JSON.stringify({ autoConnect: e.target.checked }) })
  );
  $("set-auto-start").addEventListener("change", (e) =>
    api("/api/settings", { method: "POST", body: JSON.stringify({ autoStart: e.target.checked }) })
  );
  $("set-query-state").addEventListener("change", (e) =>
    api("/api/settings", { method: "POST", body: JSON.stringify({ queryState: e.target.checked }) })
  );

  const toggleDrawer = () => {
    const collapsed = $("output-drawer").classList.toggle("collapsed");
    if (!collapsed) {
      flushLogsRender();
    }
  };
  $("sb-drawer-btn").addEventListener("click", toggleDrawer);
  $("btn-drawer-close").addEventListener("click", () => $("output-drawer").classList.add("collapsed"));
  $("sb-state-btn").addEventListener("click", () => switchView("connect"));
  $("sb-nic-btn").addEventListener("click", () => switchView("network"));

  window.addEventListener("keydown", (e) => {
    if (e.ctrlKey && e.key === "`") {
      e.preventDefault();
      toggleDrawer();
    } else if (e.ctrlKey && ["1", "2", "3", "4"].includes(e.key)) {
      e.preventDefault();
      const map = { 1: "connect", 2: "network", 3: "debug", 4: "settings" };
      switchView(map[e.key]);
    }
  });

  if (window.matchMedia) {
    window.matchMedia("(prefers-color-scheme: light)").addEventListener("change", () => {
      if ((state.config && state.config.theme) === "system") {
        applyTheme("system");
      }
    });
  }

  loadInitialState().then(startSSE);
})();
