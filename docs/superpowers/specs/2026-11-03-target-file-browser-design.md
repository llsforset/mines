# 目标文件浏览器 + 拿回文件预览（第一版）设计

日期：2026-11-03　状态：用户已确认，按此实施

## 目标

点进「目标」里的机器后，能浏览那台机器的目录结构（只列元数据，不拉文件内容），
点「下载」才把文件按块拉回来；下载完成的文件在服务端留档，前端可以直接预览
主流格式（JSON、文本、图片、PDF、音视频），也可以再存到本机。

## 范围

第一版做：目录浏览（C + Go）、下载、服务端留档、前端预览。
第二版再做：在线编辑/写回、删除/改名/建目录（C 需要新写任务）。

## 界面

- Go 目标：现有「文件」标签继续用，点文件名只选中，「下载」按钮才传输；
  新增「拿回的文件」标签。
- C 目标：页面改成 标签：终端 / 文件 / 拿回的文件。
  - 文件：路径栏 + 打开 + 刷新 + 上一级；表格列出 名称/大小/修改时间/类型；
    点目录进入下一层，文件行有「下载」按钮。
- 拿回的文件（两种目标通用）：列表 + 点行出预览 + 存到本机 + 删除记录。

## C 植入体协议

- 新任务 TLV_LIST_TASK 0x45（0x44 已被心跳提示占用）：`[task_id:4][path]`。
- 新结果 TLV_DIR_RES 0x31：`[task_id:4][err:1][truncated:1][entries…]`，
  每条 entry `[isdir:1][size:8][mtime:8][namelen:2][name]`（全部小端）。
- 单条结果必须装进 u16：entries 上限 60000 字节，装不下置 truncated。
- err：0 成功，1 不存在，2 权限/其他，3 不是目录。
- 列目录跳过 `.`/`..`；单层不递归；stat 失败的条目跳过。
- 旧植入体不认识 0x45 会忽略 → 服务端 pending 120 秒超时。
- 下载沿用现有分块读文件（48KB/心跳，上限 20MB，失败整次重来）。

## 服务端

- litebeacon：
  - TaskListDir 入队（不占文件任务名额）；结果不走通用 results 队列，
    直接进每信标的目录缓存（path → DirListing），按 TaskID 找回请求的 path。
  - RequestDir(id, path, force)：缓存 60 秒内且不 force 直接返回；同 path
    有未超时（120 秒）的 pending 不重复入队。
  - OnCompletedFile 钩子：读文件完成（含兼容旧协议的单块）时回调，web 层存档。
- web：
  - fileStore：`~/.sliver/files/index.json` + `~/.sliver/files/data/<id>`。
    记录 ID/Target(lite:xx|session:xx|beacon:xx)/SourcePath/Name/Size/At。
  - 路由：`/api/lite/ls`（POST 发起、GET 查状态）、`/api/files`（GET 列表、
    DELETE 删记录）、`/api/files/raw`（GET 内容，按扩展名给 Content-Type）。
  - Go 下载（/api/task action=download）成功后同样存档并在响应里带 Grabbed 记录。
- 目录缓存只在内存（重启即空，重新点一次就有了），留档文件落盘。

## 预览规则（前端）

- 扩展名决定渲染方式；内容永不直接 innerHTML：文本一律转义，
  图片/音视频/PDF 用 blob URL 的 img/video/audio/iframe。
- json/jsonl：JSON.parse 后缩进展示；>2MB 截断提示。
- 文本类（txt log conf ini yaml yml csv tsv md xml html 源码等）：转义 pre，
  >1MB 截断提示。
- png jpg gif webp svg bmp ico：img；pdf：iframe；mp4 webm mp3 wav：播放器。
- 其他二进制：前 2KB 十六进制 + 下载提示。

## 明确不做（第一版）

不预取整盘、不自动 ls /、C 不做上传/删除/改名、不做文本搜索、CSV 不转表格、
不做左侧目录树（后续可加）。

## 测试

- proto：dir 结果解析、listdir 任务编码、0x45/0x31 常量。
- store：请求/缓存/去重/过期、OnCompletedFile 回调、既有用例改签名。
- web：fileStore 增删查、/api/files 系列、/api/lite/ls 校验、app.js 关键字。
- darwin 功能测试：真编译 C 植入体，列目录出 sample.txt、目录 err=3。
