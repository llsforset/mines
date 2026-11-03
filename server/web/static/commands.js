const groupNames = {
  Generic: "常用",
  Network: "网络",
  Payload: "植入体",
  Data: "数据",
  Sliver: "目标",
  Core: "基本操作",
  Info: "查看信息",
  Filesystem: "文件",
  Execution: "运行程序",
  Privileges: "权限",
  Process: "进程",
  "Sliver - 3rd Party macros": "第三方快捷命令",
  "Sliver - 3rd Party extensions": "第三方扩展",
  "Sliver - Windows": "Windows 专用",
  Multiplayer: "多人一起登录",
  "其他": "其他",
};

const commandNames = {
  generate: "生成植入体",
  "generate beacon": "生成定时回来的程序",
  "generate info": "查看能编译哪些系统",
  regenerate: "按原来的配置再生成",
  sessions: "列出一直连着的机器",
  beacons: "列出定时回来的机器",
  jobs: "列出监听端口",
  mtls: "打开加密监听",
  http: "打开普通网页监听",
  https: "打开加密网页监听",
  dns: "打开域名监听",
  websites: "托管网页",
  creds: "账密",
  loot: "文件",
  hosts: "历史机器",
  operators: "登录账号",
  execute: "在机器上运行程序",
  shell: "远程命令行",
  ls: "列出文件",
  cd: "进入目录",
  pwd: "当前目录",
  cat: "查看文件内容",
  download: "下载文件",
  upload: "上传文件",
  mkdir: "新建目录",
  rm: "删除文件",
  mv: "移动文件",
  cp: "复制文件",
  ps: "列出进程",
  ping: "看这台机器还在不在",
  screenshot: "截屏",
  ifconfig: "看网卡",
  netstat: "看网络连接",
  socks5: "本地代理",
  portfwd: "把端口转过来",
  rportfwd: "把端口转过去",
  migrate: "换到另一个进程里运行",
  getsystem: "提升到系统权限",
  registry: "注册表",
};

function commandLabel(spec) {
  return commandNames[spec.id] || spec.id;
}

function groupLabel(name) {
  return groupNames[name] || name;
}

function renderCommandBrowser(root, menu, target) {
  root.innerHTML = `<div class="workbench">
    <section class="finder">
      <label>搜索<input id="cmd-search" placeholder="生成植入体、列出文件、远程命令行"></label>
      <div id="cmd-list" class="cmd-list"></div>
    </section>
    <section class="detail">
      <form id="cmd-form">
        <div class="detail-head"><h3 id="cmd-title">选择一条命令</h3><button type="submit">执行</button></div>
        <div id="cmd-flags"></div>
      </form>
      <pre class="output" id="cmd-output">这里显示命令结果。</pre>
    </section>
  </div>`;
  let specs = [];
  let current = null;
  const list = $("cmd-list");
  const draw = () => {
    const query = $("cmd-search").value.trim().toLowerCase();
    const shown = specs.filter((spec) => !query || spec.id.includes(query) || commandLabel(spec).toLowerCase().includes(query) || groupLabel(spec.group).toLowerCase().includes(query));
    const groups = [];
    shown.forEach((spec) => { if (!groups.includes(spec.group)) groups.push(spec.group); });
    list.innerHTML = groups.map((group) => `<p class="group-label">${esc(groupLabel(group))}</p>` + shown.filter((spec) => spec.group === group).map((spec) => `<button type="button" data-id="${esc(spec.id)}" class="${current && current.id === spec.id ? "active" : ""}" title="${esc(spec.id)}">${esc(commandLabel(spec))}</button>`).join("")).join("");
    list.querySelectorAll("button").forEach((button) => {
      button.onclick = () => {
        current = specs.find((spec) => spec.id === button.dataset.id);
        drawForm();
        draw();
      };
    });
  };
  const drawForm = () => {
    if (!current) return;
    $("cmd-title").textContent = commandLabel(current);
    const positional = current.use && current.use.includes(" ") ? current.use.split(" ").slice(1).join(" ") : "";
    const flags = (current.flags || []).map((flag) => {
      if (flag.type === "bool") return `<label><input data-flag="${esc(flag.name)}" data-type="bool" type="checkbox"> ${esc(flag.name)} <span class="hint">${esc(flag.usage)}</span></label>`;
      return `<label>${esc(flag.name)} <span class="hint">${esc(flag.usage)}</span><input data-flag="${esc(flag.name)}" data-type="${esc(flag.type)}" placeholder="${esc(flag.default || "")}"></label>`;
    }).join("");
    $("cmd-flags").innerHTML = `<p class="hint">${esc(current.short || "")}</p>` + (positional ? `<label>位置参数 ${esc(positional)}<input id="cmd-pos" placeholder="按命令行顺序填写"></label>` : `<input id="cmd-pos" type="hidden">`) + flags;
  };
  $("cmd-search").oninput = draw;
  $("cmd-form").onsubmit = async (event) => {
    event.preventDefault();
    if (!current) return;
    const args = current.path.slice();
    const pos = $("cmd-pos") && $("cmd-pos").value.trim();
    if (pos) args.push(...splitArgs(pos));
    $("cmd-flags").querySelectorAll("[data-flag]").forEach((input) => {
      if (input.dataset.type === "bool") {
        if (input.checked) args.push("--" + input.dataset.flag);
        return;
      }
      if (!input.value) return;
      if (input.dataset.type === "stringSlice" || input.dataset.type === "stringArray") {
        input.value.split(",").map((part) => part.trim()).filter(Boolean).forEach((part) => args.push("--" + input.dataset.flag, part));
        return;
      }
      args.push("--" + input.dataset.flag, input.value);
    });
    $("cmd-output").textContent = "执行中…\n" + args.join(" ");
    try {
      const result = await api("/api/exec", {
        method: "POST",
        json: {
          menu,
          sessionID: target && target.kind === "session" ? target.ID : "",
          beaconID: target && target.kind === "beacon" ? target.ID : "",
          args,
        },
      });
      $("cmd-output").textContent = [result.output, result.error].filter(Boolean).join("\n\n") || "完成，没有输出。";
    } catch (err) {
      $("cmd-output").textContent = err.message;
    }
  };
  api("/api/commands?menu=" + menu).then((data) => {
    specs = data.commands || [];
    $("cmd-output").textContent = `已载入 ${specs.length} 条${menu === "implant" ? "这台机器可以执行的" : "服务器"}命令。`;
    draw();
  }).catch((err) => {
    $("cmd-output").textContent = err.message;
  });
}

function renderTerminal(box) {
  if (!state.selected || state.selected.kind !== "session") {
    box.innerHTML = `<p class="hint">远程命令行只能连一直在线的机器。定时回来的机器请用「全部命令」里的「在机器上运行程序」。</p>`;
    return;
  }
  box.innerHTML = `<div class="panel">
    <button type="button" id="shell-open">打开远程命令行</button>
    <pre class="output" id="shell-log"></pre>
    <form id="shell-form" class="row"><input id="shell-input" placeholder="输入后回车"><button type="submit">发送</button></form>
  </div>`;
  let socket;
  $("shell-open").onclick = () => {
    if (socket) socket.close();
    const protocol = location.protocol === "https:" ? "wss" : "ws";
    socket = new WebSocket(`${protocol}://${location.host}/api/shell?session=${encodeURIComponent(state.selected.ID)}&token=${encodeURIComponent(state.token)}`);
    socket.binaryType = "arraybuffer";
    $("shell-log").textContent = "正在连接...\n";
    socket.onmessage = (event) => {
      const text = typeof event.data === "string" ? event.data : new TextDecoder().decode(event.data);
      $("shell-log").textContent += text;
      $("shell-log").scrollTop = $("shell-log").scrollHeight;
    };
    socket.onerror = () => { $("shell-log").textContent += "\n连接失败\n"; };
  };
  $("shell-form").onsubmit = (event) => {
    event.preventDefault();
    if (!socket || socket.readyState !== 1) return;
    socket.send(new TextEncoder().encode($("shell-input").value + "\n"));
    $("shell-input").value = "";
  };
}

function splitArgs(value) {
  const args = [];
  const pattern = /"([^"]*)"|'([^']*)'|(\S+)/g;
  let match;
  while ((match = pattern.exec(value))) args.push(match[1] ?? match[2] ?? match[3]);
  return args;
}
