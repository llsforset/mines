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

## 3. 协议设计

### 3.1 载荷编码

```
HTTP body = base64( nonce[12] || AES-256-GCM(key, nonce, plaintext) )
plaintext = TLV 帧序列：[type:1B][len:2B LE][value:lenB] 串接
```

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
| 0x20 | exec 结果 | [task_id u32][exit i32][output ≤64KB] |
| 0x30 | 文件结果 | [task_id u32][err u8][content ≤512KB] |

下行（服务器 → 植入体，任务队列逐个下发）：

| 类型 | 名称 | 值结构 |
|---|---|---|
| 0x40 | exec 任务 | [task_id u32][timeout_sec u16][cmd bytes] |
| 0x41 | 读文件任务 | [task_id u32][path bytes] |
| 0x42 | 调整间隔 | [interval_sec u32][jitter_pct u8] |
| 0x43 | 退出 | 空（植入体收到后静默退出） |

### 3.3 HTTP 语义

- 单一端点：`POST /<path>`，path 为启动监听器时配置的普通字符串
  （默认 `/upload`）。
- 成功：200 + 应答体（同格式编码的下行 TLV；无任务时空任务帧）。
- secret 未登记 / 解密失败 / 时间戳过期：404 + 空体，端点不暴露存在性。
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

- 配置（URL、secret、间隔、jitter、路径）由 build.sh 生成 `config.h`，
  内含随机单字节 XOR 混淆的字节数组，运行时解码，产物内搜不到明文 C2 域名。
- 编译 `-Os -s -fno-ident -fno-unwind-tables`，无符号无调试信息。
- 代码内不出现 "beacon/implant/sliver" 等字符串；源码符号命名中性。

### 4.2 服务端 — `server/litebeacon/`

- `Start(host, port, path) / Stop()` 单实例监听器，TLS 证书复用
  `certs.HTTPSGenerateRSACertificate`（自签，存于 `~/.sliver/certs/https/`）。
- secret 登记：持久化于 `~/.sliver/litebeacon/secrets.json`，全部有效，
  支持多信标共存与轮换。
- 内存态：每个信标的待下发任务队列（上限 32）与结果环形缓冲
  （上限 32 条、总量 1MB），互斥锁保护。
- 监听器生命周期由 Web 控制台管理，不接入 rpc/jobs 系统（v1 从简）。

### 4.3 Web 控制台 — `server/web/` 扩展

新增 API（走现有 token 鉴权）：

| 端点 | 说明 |
|---|---|
| `POST /api/lite/listener/start` | {host, port, path} |
| `POST /api/lite/listener/stop` | |
| `POST /api/lite/config` | 签发新 secret（旧 secret 保留有效），返回 url、secretHex、可直接保存的 config.h 文本 |
| `GET /api/lite/config` | 返回最新 secret 与对应 config.h 文本（不新建） |
| `GET /api/lite/beacons` | 信标列表：id/主机信息/firstSeen/lastSeen |
| `POST /api/lite/task` | {beaconId, type: exec\|read, cmd\|path} → taskId |
| `GET /api/lite/results` | ?beacon=xx 取回结果（读取即消费） |

`static/app.js` 新增「轻量信标」面板：监听器启停、config.h 下发、
信标表、任务下发表单、结果查看。样式沿用现有面板。

## 5. 错误处理

- 植入体：网络失败退避重试；命令执行失败以非零 exit code + stderr 文本
  作为结果回传；文件读取失败回 err 码（1=不存在 2=拒绝 3=超大）。
- 服务端：解密失败/未知信标一律 404；队列满丢弃最旧任务并记录日志；
  结果缓冲超限丢最旧。
- 命令输出上限 64KB，文件内容上限 512KB，超限截断并在 TLV err 位标注。

## 6. 测试计划

- Go 单测（`./go-tests.sh`）：AEAD 加解密回环（多 secret 场景）、TLV
  编解码边界、httptest 起监听器做完整 checkin→下发→回传回环、404 路径。
- 端到端（Linux 版）：docker 内构建产物，对宿主机服务端走
  `host.docker.internal` 完成上线与命令回传验证。
- Windows 版：docker mingw 交叉编译验证产物可构建、体积、`strings`
  卫生检查；目标机功能由操作人验证（协议核心与 Linux 版共用）。

## 7. 交付物清单

1. `implant/lite/`：main.c / win.c / linux.c / build.sh / Dockerfile
2. `server/litebeacon/`：监听器 + 协议 + 任务存储 + 单测
3. `server/web/`：6 个 API + 面板 UI
4. 构建产物体积与 `strings` 卫生验证记录（实现阶段输出）
