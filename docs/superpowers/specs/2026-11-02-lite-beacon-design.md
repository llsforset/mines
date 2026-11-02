# 轻量 C 植入体（lite beacon）设计文档

日期：2026-11-02
状态：已确认（与操作人两轮问答后定稿）

## 1. 背景与目标

现有 Go 植入体（`implant/sliver`）功能完整但体积约 22MB，静态特征多。
本次新增一个 C 语言编写的轻量植入体，作为独立选项与 Go 版并存：

- **目标平台**：Linux x64 + Windows x64（协议核心共用，传输层分平台实现）
- **回传通道**：仅 HTTPS
- **v1 能力边界**：主机信息上线、执行命令并回传输出、读取指定文件回传
- **体积目标**：单文件产物 20-40KB（strip 后）
- **不改动**现有 Go 植入体的生成链路，Go 版仍是控制台默认选项

不在 v1 范围内：文件上传、驻留、注入、EDR 对抗、staging、代理/隧道、
macOS/arm、从 Web 控制台触发 C 编译。

## 2. 总体架构

```
C 植入体 (win: WinHTTP / linux: OpenSSL)        Go 植入体（现有，不动）
        │ HTTPS POST，TLV over AEAD                  │ 完整 Sliver 协议
        ▼                                            ▼
  litebeacon 监听器（新，独立端口，自签 TLS）       现有 HTTPS C2 监听器
        │                                            │
        ▼                                            ▼
  Web 控制台「轻量信标」面板                    现有会话/beacon 面板
```

C 版不复刻 Sliver 协议（age 密钥交换 + protobuf 信封 + minisign 签名链在
C 里实现成本高且抵消体积目标），走独立的极简二进制协议，服务端新增
`server/litebeacon` 包承载监听与任务队列。

### 安全模型

- TLS 只承担传输加密与流量外观，不承担身份认证：
  - Windows 用 WinHTTP（Schannel），忽略证书错误；
  - Linux 用 OpenSSL，`SSL_VERIFY_NONE`。
- 任务数据真伪由载荷层 AES-256-GCM 保证，密钥为构建时生成的 32 字节
  随机共享密钥。无密钥者无法伪造任务（服务端→植入体方向）或伪造结果，
  也无法读取载荷内容，即便 TLS 被企业代理解密。
- 已知取舍：持有共享密钥前的中间人最多做到丢弃流量（降级为 DoS），
  无法注入。接受该取舍。

### 流量外形（外部特征对抗）

安全设备的识别点在加密之外的可观测外形，逐项对照并给出设计约束：

**TLS 指纹：C 版天然规避 Go 特征。** 植入体不使用 Go TLS——Windows 走
WinHTTP（Schannel，与 Windows 系统组件、大量桌面软件同栈），Linux 走
OpenSSL（与 curl 及大量 C/S 软件同栈）。握手指纹呈现为「普通系统软件」
而非「Go 程序」，这是 C 重写相对 Go 版最大的外形收益。服务端 TLS 指纹
为常规 Go `crypto/tls`，如需进一步遮蔽可按常规做法前置 nginx/CDN 回源
（运维选项，不纳入实现）。不使用客户端证书，永不使用双向 TLS。

**证书：不复用 Sliver 的证书生成特征。** Sliver `randomSubject` 生成的
自签证书已被公开规则覆盖，lite 监听器另行生成无个性的自签证书；ACME
签发**列为 v1 后续项**：`ensureTLSCert` 优先加载 `~/.sliver/litebeacon/tls.pem|tls.key`，
运维可先在其他工具里用 ACME 签发后直接换入这两个文件（复用现有
`certs/acme.go` 做控制台自动签发是 v2 范围）。AEAD 仍承担全部身份认证，
证书仅影响外形。

**连接节奏：随机化打破心跳规律。** 无长连接——每次回连只有一条短命
POST，连接即断。间隔逐轮重算，而非固定值加小抖动：

- 首连延迟 uniform(5, 30) 秒，切断「部署→立即上线」的时间关联；
- 下一轮间隔 = base × uniform(0.5, 1.7)，另有 8% 概率再乘
  uniform(2.0, 3.0)，让长期间隔直方图不聚簇；
- base 默认 180 秒，构建时可调；
- 任务完成后的结果回传延迟 uniform(1, 4) 秒，拆开「收到任务→立刻
  回连」的强关联。

**HTTP 外形：呈现软件遥测客户端，不冒充浏览器。** UA 必须与 TLS 栈
自洽——schannel/OpenSSL 的握手不是浏览器，用 Chrome UA 与 sec-ch-ua
头部会形成「头说是浏览器、握手不是」的自相矛盾。因此呈现低存在感的
同步/遥测客户端外形：完整但非浏览器的头部集（Host、UA、Accept:
application/json、Accept-Language、Content-Type），UA 从构建期配置池
中固定选取一个真实软件组件 UA；载荷外层 JSON 信封（见 3.1）；体长经
0x0F 填充 TLV 逐次变化；监听器应答头为普通 JSON 服务外观，不携带
Sliver 默认 profile 的响应头特征。

## 3. 协议设计

### 3.1 载荷编码

```
HTTP body = {"<key>": "<base64( nonce[12] || AES-256-GCM(key, nonce, plaintext) )>"}
plaintext = TLV 帧序列：[type:1B][len:2B LE][value:lenB] 串接
```

- 外层为 JSON 信封：`<key>` 为构建期从候选池选定的普通字段名，请求
  Content-Type 为 `application/json`，避免裸发高熵 base64 体。
- 请求与应答同格式。

- AES-256-GCM，nonce 随机 12 字节。
- `key = SHA-256( secret || "litebeacon/aead/v1" )`，secret 为 32 字节
  共享密钥。服务器对所有已登记 secret 逐一尝试解密（AEAD 认证失败即换）。
- base64 标准 alphabet，避免 body 里出现二进制异常内容。
- 请求时间戳在明文 TLV 内，服务器校验 ±300 秒新鲜度；每个信标保留
  最近 64 个 nonce 哈希做重放窗口。

### 3.2 TLV 类型表（小端序）

上行（植入体 → 服务器）：

| 类型 | 名称 | 值结构 |
|---|---|---|
| 0x01 | beacon_id | 16 字节 ASCII（派生见 3.4） |
| 0x02 | timestamp | uint64 Unix 秒 |
| 0x10 | hostname | 字符串（首次上线携带） |
| 0x11 | os | 字符串 |
| 0x12 | arch | 字符串 |
| 0x13 | username | 字符串 |
| 0x14 | pid | uint32 |
| 0x20 | exec 结果 | [task_id u32][exit i32][output ≤60KB] |
| 0x30 | 文件结果 | [task_id u32][err u8][content ≤60KB] |

下行（服务器 → 植入体，任务队列逐个下发）：

| 类型 | 名称 | 值结构 |
|---|---|---|
| 0x40 | exec 任务 | [task_id u32][timeout_sec u16][cmd bytes] |
| 0x41 | 读文件任务 | [task_id u32][path bytes] |
| 0x42 | 调整间隔 | [interval_sec u32][jitter_pct u8] |
| 0x43 | 退出 | 空（植入体收到后静默退出） |
| 0x44 | 间隔提示 | uint32 秒（5..86400，植入体超界忽略；每轮应答必带） |

任意方向均可插入 0x0F 填充 TLV：值为随机字节（0-256B），接收方解出后
忽略，用于消除请求/响应体长度的定长聚簇特征。

**自适应回连间隔（v1.1）**：服务器每轮在 0x44 里下发植入体的下一轮
间隔基准。策略：操作员 5 分钟内给该信标排过任务或拉过结果（活跃窗口）
→ 下发 fastSec；否则下发该信标的基准值（sleep 任务 0x42 可设单信标
基准，未设时为监听器空闲值 idleSec）。两档均为监听器启动参数（clamp
5..86400），默认都是 10s；植入体仅照做 0x44，不维护本地策略。首轮
间隔由 config.h 的 CFG_INTERVAL（=签发时的空闲值）决定，之后完全由
0x44 接管。纯轮询的数学极限不变：空闲期排的第一个命令最坏等待一个
空闲间隔才被捡起。

### 3.3 HTTP 语义

- 单一端点：`POST /<path>`，path 为构建期配置的普通字符串
  （默认 `/api/v2/sync`，可改）。
- 成功：200 + 应答体（同格式编码的下行 TLV；无任务时空任务帧）。
- secret 未登记 / 解密失败 / 时间戳过期 / 重放：与其他未知请求一致，
  返回 nginx 风格 404 页面，端点不暴露存在性。
- GET 及其他路径：返回静态的普通站点缺省页（nginx 风格 404 页面），
  使监听端口看起来是台普通 Web 服务器。
- 植入体侧：失败静默退避（1s 起指数递增，上限 = 当前回连间隔），
  连续失败不退出。

### 3.4 信标 ID

`id = hex( SHA-256( secret || hostname || username )[0..8] )`，16 个 hex
字符。稳定、无需落盘、同机不同密钥互不冲突。

## 4. 组件设计

### 4.1 C 植入体 — `implant/lite/`

```
main.c    配置解码、回连循环（间隔+jitter）、TLV 编解码、任务分发（可移植 C99）
win.c      WinHTTP 传输、CreateProcess+管道执行（cmd.exe /c，超时杀进程）、
           CreateFile 读文件、Sleep/随机 jitter
linux.c    OpenSSL 传输、/bin/sh -c 执行（外层包 `timeout N` 兜底超时）、
           open/read 读文件、nanosleep
build.sh   参数：--platform win|linux --url --secret-hex --interval --jitter --out
Dockerfile debian 构建 env：gcc + libssl-dev + gcc-mingw-w64-x86-64 + binutils
```

- 配置（URL、路径、secret、间隔、UA、JSON 字段名、节奏算法参数）由
  build.sh 生成 `config.h`，内含随机单字节 XOR 混淆的字节数组，运行时
  解码，产物内搜不到明文 C2 域名。
- 编译 `-Os -s -fno-ident -fno-unwind-tables`，无符号无调试信息。
- 代码内不出现 "beacon/implant/sliver" 等字符串；源码符号命名中性。

### 4.2 服务端 — `server/litebeacon/`

- `Start(host, port, path) / Stop()` 单实例监听器；TLS 证书自签生成，
  subject 为无个性普通值（不复用 Sliver `randomSubject` 的生成特征），
  存于 `~/.sliver/litebeacon/`；对外正式目标支持 ACME 签发
  （复用现有 `certs/acme.go`），消除企业代理的不可信证书告警面。
- secret 登记：持久化于 `~/.sliver/litebeacon/secrets.json`，全部有效，
  支持多信标共存与轮换。
- 内存态：每个信标的待下发任务队列（上限 32）与结果环形缓冲
  （上限 32 条、总量 1MB），互斥锁保护。
- 监听器生命周期由 Web 控制台管理，不接入 rpc/jobs 系统（v1 从简）。

### 4.3 Web 控制台 — `server/web/` 扩展

新增 API（走现有 token 鉴权）：

| 端点 | 说明 |
|---|---|
| `POST /api/lite/listener/start` | {host, port, path, url, idleSec, fastSec}，idle/fast 为自适应间隔两档（clamp 5..86400，默认 10/10） |
| `POST /api/lite/listener/stop` | |
| `POST /api/lite/config` | 签发新 secret（旧 secret 保留有效），返回 url、secret（base64）、可直接保存的 config.h 文本 |
| `GET /api/lite/config` | 返回最新 secret 与对应 config.h 文本（不新建） |
| `GET /api/lite/beacons` | 信标列表：id/主机信息/firstSeen/lastSeen |
| `POST /api/lite/task` | {beaconId, type: exec\|read, cmd\|path} → taskId |
| `GET /api/lite/results` | ?beacon=xx 取回结果（读取即消费） |
| `POST /api/lite/beacon/delete` | 从列表删除信标（控制台清理用，非植入体功能） |

`static/app.js` 新增「轻量信标」面板：监听器启停、config.h 下发、
信标表、任务下发表单、结果查看。样式沿用现有面板。

## 5. 错误处理

- 植入体：网络失败退避重试；命令执行失败以非零 exit code + stderr 文本
  作为结果回传；文件读取失败回 err 码（1=不存在 2=拒绝 3=超大）。
- 服务端：解密失败/未知信标一律 404；队列满丢弃最旧任务并记录日志；
  结果缓冲超限丢最旧。
- 命令输出上限 60KB（超限截断）；文件内容上限 60KB（超限回 err=3，
  不截断）。上限刻意低于 TLV u16 长度字段极限（65535），避免单帧溢出，
  也避免巨型加密 POST 暴露流量外形。更大的文件应拆成多条任务。

## 6. 测试计划

- Go 单测（`./go-tests.sh`）：AEAD 加解密回环（多 secret 场景）、TLV
  编解码边界、httptest 起监听器做完整 checkin→下发→回传回环、404 路径。
- 端到端（Linux 版）：docker 内构建产物，对宿主机服务端走
  `host.docker.internal` 完成上线与命令回传验证。
- Windows 版：docker mingw 交叉编译验证产物可构建、体积、`strings`
  卫生检查；目标机功能由操作人验证（协议核心与 Linux 版共用）。
- 外形自检：抓包核对请求头集合与 UA 自洽、TLS 指纹非 Go 客户端栈、
  请求体长度多次采样不聚簇；服务端核对无 Sliver 默认 profile 响应头。

## 7. 交付物清单

1. `implant/lite/`：main.c / win.c / linux.c / build.sh / Dockerfile
2. `server/litebeacon/`：监听器 + 协议 + 任务存储 + 单测
3. `server/web/`：6 个 API + 面板 UI
4. 构建产物体积与 `strings` 卫生验证记录（实现阶段输出）
