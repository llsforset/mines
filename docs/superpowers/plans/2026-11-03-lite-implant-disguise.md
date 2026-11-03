# C 植入体外观伪装实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** C 植入体可伪装成正常软件：Windows 版本资源+图标+GUI 子系统，三平台运行时进程名。

**Architecture:** 伪装字段随生成请求进 `litebeacon.Build`；Windows 目标在编译目录生成 `.rc`/`.ico`，`zig rc` 编成 `.res` 链入并设 GUI 子系统；进程名经 `config.h` 的 `CFG_PNAME`（XOR 混淆）下发，`main.c` 解码后调平台钩子。

**Tech Stack:** Go 1.x（标准库 encoding/base64）、Zig 0.17（`rc` + `cc`）、C99。

## Global Constraints

- 伪装字段全部可选；为空时产物行为与现状一致（不出 `.rc`、不出 `CFG_PNAME`）。
- 文本字段仅允许可打印 ASCII（0x20–0x7E），禁 `"` 与 `\`，各 ≤64 字符；进程名 ≤15 字符。
- 版本号 ≤4 段数字，每段 ≤65535，不足补零。
- 图标 ≤256KB，魔数 `00 00 01 00`，条目 ≤32。
- 厂商/图标用虚构素材；不引用真实公司名。
- 编译失败路径与现有「编译失败」错误一致；不新增静默降级。
- 测试：`./go-tests.sh` 或针对包的 `go test`；链接级验证用 `LITE_DISGUISE_LINK=1` 开关。

---

### Task 1: `server/litebeacon/disguise.go` — 校验与资源生成

**Files:**
- Create: `server/litebeacon/disguise.go`
- Test: `server/litebeacon/disguise_test.go`

**Interfaces:**
- Produces: `type DisguiseSpec struct { DisplayName, Company, Version, ProcName string; Icon []byte }`、
  `ParseDisguise(display, company, version, procName string) (*DisguiseSpec, error)`、
  `SetIcon(spec *DisguiseSpec, iconB64 string) error`、`generateRC(spec *DisguiseSpec, hasIcon bool, originalFilename string) []byte`

- [ ] Step 1: 写失败测试（转义拒绝、版本归一化、ico 魔数/超限、预设常量）
- [ ] Step 2: `go test ./server/litebeacon -run TestDisguise` → FAIL（未定义）
- [ ] Step 3: 实现 `disguise.go`（含内置 `bundledIconB64`）
- [ ] Step 4: 测试通过 → `git commit`

### Task 2: `configgen.go` — CFG_PNAME

**Files:**
- Modify: `server/litebeacon/configgen.go`
- Test: `server/litebeacon/secrets_test.go`（或同包新用例）

**Interfaces:**
- Consumes: `DisguiseSpec.ProcName`
- Produces: `ConfigParams.ProcName string`；`config.h` 内 `#define CFG_PNAME_LEN n` + XOR 数组 `CFG_PNAME`；空则完全不输出

- [ ] Step 1: 失败测试：ProcName 为空不输出；非空可按 `CFG_XOR` 解回原文
- [ ] Step 2: FAIL → 实现 → PASS → commit

### Task 3: `compile.go` — 请求字段与 Windows 资源链接

**Files:**
- Modify: `server/litebeacon/compile.go`（BuildRequest、Build、compileImplant）
- Test: `server/litebeacon/disguise_test.go`（链接级用例，`LITE_DISGUISE_LINK=1` 门控）

**Interfaces:**
- Consumes: Task 1 的 `ParseDisguise/SetIcon/generateRC`；Task 2 的 `ConfigParams.ProcName`
- Produces: `BuildRequest{DisplayName, Company, Version, ProcName, IconB64}`；`compileImplant(cfgH, goos, goarch, spec *DisguiseSpec)`

- [ ] Step 1: 失败测试：BuildRequest 无伪装字段 → 编译不过（字段不存在）
- [ ] Step 2: 实现：Build 组装 spec（仅 windows 目标使用）；compileImplant 写 `.rc`/`icon.ico`，`zig rc -- disguise.rc disguise.res`，失败带输出报错；args 追加 `.res` 与 `-Xlinker /subsystem:windows`
- [ ] Step 3: 单测 PASS；`LITE_DISGUISE_LINK=1` 手动跑：断言子系统位==2、UTF-16 "Customer Experience Program" 在产物中 → commit

### Task 4: `server/web/lite_build.go` — 接收伪装字段

**Files:**
- Modify: `server/web/lite_build.go`

- [ ] Step 1: body 增 `DisplayName/Company/Version/ProcName/IconB64`，透传给 `litebeacon.Build`
- [ ] Step 2: `go build ./server/web` + 现有 web 测试 PASS → commit

### Task 5: `app.js` — 表单与预设

**Files:**
- Modify: `server/web/static/app.js`（renderCImplant）

- [ ] Step 1: 加「伪装预设」下拉（不伪装/体验计划代理）+ 显示名/厂商/版本号/进程名/图标上传；选预设自动填，选「不伪装」清空
- [ ] Step 2: 提交时 displayName 非空才带字段；图标 FileReader→base64，>256KB 前端直接提示
- [ ] Step 3: `node --check server/web/static/app.js` → commit

### Task 6: 植入体 C 改动 — 进程名

**Files:**
- Modify: `implant/lite/port.h`、`implant/lite/linux.c`、`implant/lite/darwin.c`、`implant/lite/win.c`、`implant/lite/main.c`

**Interfaces:**
- Consumes: `CFG_PNAME`、`CFG_XOR`、`deob()`
- Produces: `void sys_set_procname(const char *name);`（linux=prctl(PR_SET_NAME)，darwin/win=空实现）；`main(int argc, char **argv)` 保存 argv0 后原地改写

- [ ] Step 1: port.h 加声明；三平台实现；main.c 签名改 `main(int argc, char **argv)`，解码后 `#ifdef CFG_PNAME` 应用进程名（prctl + argv0 截断改写 + 清零）
- [ ] Step 2: `TestDarwinImplantStillWorks` PASS（host clang 编译真实源码）→ commit

### Task 7: 全量验证

- [ ] `gofmt -w` 改动文件；`node --check` app.js
- [ ] `go test ./server/litebeacon ./server/web`（unit）全绿
- [ ] `LITE_DISGUISE_LINK=1` 链接级用例 PASS
- [ ] 重建 `sliver-server`，重启守护进程；curl `/api/implants/generate-c`（windows + 伪装字段）→ Python 断言子系统=2、UTF-16 串存在、图标资源存在
- [ ] curl 不带伪装字段 → 行为与现状一致（200 且无 `.rsrc` 版本串）
- [ ] commit 收尾

## Self-Review

- Spec 覆盖：表单/预设(Task5)、资源+图标+子系统(Task1/3)、CFG_PNAME+三平台(Task2/6)、错误路径(Task1/3)、测试(Task1/2/3/7) —— 无缺口。
- 类型一致：`DisguiseSpec` 字段名各任务一致；`CFG_PNAME` 与 main.c `#ifdef` 一致。
- 无占位符。
