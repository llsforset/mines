# C 植入体外观伪装设计

日期：2026-11-03

## 目标

让 C 植入体在文件外观与进程显示上像正常软件：Windows 版本资源与图标、
无控制台窗口、三平台进程名。只解决「人眼审查」，不承诺降低杀软检出
（杀软看签名、哈希、行为，与外观无关，这一点在界面文案里向操作员说明）。

## 伪装身份（预设 B，唯一内置预设）

| 字段 | 值 |
|---|---|
| FileDescription / 显示名 | Customer Experience Program |
| ProductName | Feedback Telemetry Agent |
| CompanyName | Nimbus Software Ltd. |
| FileVersion / ProductVersion | 2.0.3.0 |
| OriginalFilename | feedbackagent.exe |
| 进程名（≤15 字符） | feedbackagent |
| 图标 | 自绘：灰色圆环加脉冲点 |

厂商用虚构名称，不使用真实公司名与真实产品图标（版权与指纹）。

## 表单（server/web/static/app.js — renderCImplant）

新增「伪装」一组，全部可选，留空 = 完全维持现状（不生成资源、不改进程名）：

- 预设下拉：`不伪装` / `体验计划代理`（选 B 时自动填下列字段，仍可手改）
- 显示名、厂商、版本号（选预设自动填 2.0.3.0；自定义时留空按 1.0.0.0 处理）
- 图标：可选上传 `.ico`，≤256KB，以 base64 放进现有 JSON 请求体

## Windows 文件伪装（server/litebeacon）

仅 `windows/amd64` 且至少填了显示名时启用：

1. 新文件 `server/litebeacon/disguise.go`：由伪装字段生成 `.rc`
   （VERSIONINFO：FileDescription/ProductName/CompanyName/FileVersion/
   OriginalFilename + Translation 0x409/1200）；有图标则一并写 `.ico`
   并在 `.rc` 头部加 `1 ICON "icon.ico"`。
2. `compileImplant`：`zig rc -- disguise.rc disguise.res` 编进临时目录，
   失败时把输出进编译日志并返回错误（与其他编译错误同路径）。
3. 链接参数追加 `-Xlinker /subsystem:windows`（GUI 子系统，双击不弹黑窗）。
   任务管理器列表显示 FileDescription。
4. 产物文件名仍由「名称」字段决定（现有 sanitizeFile），要伪装成
   `feedbackagent.exe` 就把名称填成它。

已实测：`zig rc` 产出 MSVC .res 并成功链接，版本串以 UTF-16 进入
`.rsrc`；图标（自造 16×16 32bpp ico）嵌入后体积增量正确；
`-Xlinker /subsystem:windows` 将子系统位置为 2（GUI）。

## 进程名（运行时，三平台）

- `GenerateConfigH` 新增 `CFG_PROCNAME`：与现有字段同样 XOR 混淆
  存储，运行时解码；默认取显示名。
- Linux：`linux.c` 入口 `prctl(PR_SET_NAME)`（15 字节内）+ `main()`
  原地改写 `argv[0]`（新名更长则截断到原 argv[0] 长度）。
- macOS/iOS：`darwin.c` 同样改写 `argv[0]`；平台钩子分文件实现，
  `main.c` 保持 C99 可移植。
- Windows：不额外改（GUI + FileDescription 已覆盖显示）。

## 错误处理与边界

- `.ico` 非法（魔数/尺寸超限）、版本号格式不对：请求期直接报错，
  不进入编译。
- `zig rc` 失败：编译日志可见，编译失败返回。
- 资源字符串必然明文存在于 `.rsrc`（PE 资源本身如此），现有
  hygiene 检查（`beacon|implant|sliver`）不受影响。
- macOS Gatekeeper/签名不在范围；Linux 不做文件外观（ELF 无对应
  概念），仅进程名。

## 测试

- 单测：`.rc` 生成与字段转义；`CFG_PROCNAME` 混淆编解码往返；
  `.ico` 校验（魔数、大小上限）。
- 链接级验证走环境开关 `LITE_DISGUISE_LINK=1`：真实编 windows exe，
  断言子系统位、UTF-16 版本串存在。
- 不填伪装字段时走原路径，现有 `darwin_func_test` 等不受影响。

## 涉及文件

- `server/litebeacon/disguise.go`（新增）：rc/ico 生成与校验
- `server/litebeacon/compile.go`：windows 目标接资源与子系统参数
- `server/litebeacon/configgen.go`（GenerateConfigH）：CFG_PROCNAME
- `implant/lite/{main.c,linux.c,darwin.c,port.h}`：进程名钩子
- `server/web/lite_build.go`：接收伪装字段（含 base64 图标）
- `server/web/static/app.js`：表单与预设下拉
- `server/litebeacon/disguise_test.go`、`openssl_test.go` 同款开关测试
