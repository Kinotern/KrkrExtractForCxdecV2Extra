# KrkrExtractV2 (For CxdecV2)

本项目由 GPT-4.5 / Codex 辅助编写、整理和增强，面向 Wamsoft / KiriKiri Z Hxv4 2021.11+ / CxdecV2 系列加密游戏，提供一套动态分析与资源整理工具。

主要功能：

- XP3 动态解包
- 运行时字符串 Hash 映射提取
- 运行时 Key 参数提取
- 根据 `XP3 动态解包` 和 `运行时字符串 Hash 映射提取` 还原资源目录名、文件名和后缀。`实测成功率在90%以上`

## 环境

- 系统：Windows 7 SP1 x64 及以上，推荐 Windows 10 / Windows 11
- IDE：Visual Studio 2022
- 编译器：MSVC 2022
- 平台：x86 / Win32
- SDK：Windows 10 SDK 10.0.19041.0 或更新版本

## 模块说明

- `CxdecExtractorLoader.exe`  
  主加载器。负责启动目标游戏并注入对应模块，也内置资源文件名还原功能。

- `CxdecExtractor.dll`  
  解包核心。定位游戏内部 Cxdec 接口并执行 XP3 资源提取。

- `CxdecExtractorUI.dll`  
  XP3 批量解包界面。支持拖入多个 `*.xp3` 文件排队解包。

- `CxdecStringDumper.dll`  
  运行时字符串 Hash 映射提取模块。用于记录明文目录名、文件名和 Hash 的对应关系。

- `CxdecKeyDumper.dll`  
  运行时 Key 提取模块。用于导出 CxdecV2 / Hxv4 相关解密参数。

- `ExtractorOutputRestorer`  
  Loader 内置的资源文件名还原功能。读取 `Extractor_Output` 和 `StringHashDumper_Output`，生成 `Restored_Extractor_Output`。

## 当前功能

### 1. XP3 批量解包

- 支持一次拖入多个 `*.xp3` 文件排队解包。
- 支持持续追加任务，不需要等待当前任务结束后再继续拖入。
- 提供列表状态、总进度、单文件进度、成功/失败反馈。
- 支持自定义输出目录。
- 支持完成弹窗和完成提示音。
- 为了兼容宿主游戏运行时，当前采用“批量队列 + 单 worker 后台解包”模式，而不是单进程多线程并发解包。

默认输出目录：

```text
游戏目录\Extractor_Output\
```

输出内容包括：

- 解包后的 Hash 目录结构
- 与封包同名的 `.alst` 文件表
- `Extractor.log`
- `ExtractorUI.log`

### 2. 字符串 Hash 提取

运行时提取目录名和文件名的 Hash 映射，输出到：

```text
游戏目录\StringHashDumper_Output\
```

主要文件：

- `DirectoryHash.log`
- `FileNameHash.log`
- `Universal.log`

日志格式大致为：

```text
明文字符串##YSig##Hash
```

其中：

- `DirectoryHash.log` 用于还原目录名。
- `FileNameHash.log` 用于还原文件名和后缀。
- `Universal.log` 记录 Hash Seed、Salt 等辅助信息。

### 3. Key 提取

原生 C++ 版 Key 提取模块已经实现，不再依赖 Frida。

运行方式：

- 通过 `CxdecExtractorLoader.exe` 选择 `加载Key提取模块`
- Loader 会显示提取进度条和百分比
- 提取完成后弹出确认框
- 点击确认后关闭 Loader 窗口

当前进度为阶段式进度：

- `0%`：等待提取开始
- `33%`：已抓到一组关键数据
- `66%`：已抓到两组关键数据
- `100%`：全部完成

默认输出目录：

```text
游戏目录\ExtractKey_Output\
```

输出文件：

- `key_output.txt`  
  文本格式，尽量对齐 Frida 脚本输出风格。

- `KeyInfo.log`  
  详细日志。

- `KeyInfo.json`  
  结构化结果。

- `control_block.bin`  
  控制块数据。

`key_output.txt` 当前会输出：

- `load ... at ...`
- `hxpoint at ...`
- `cxpoint at ...`
- `* key : ...`
- `* nonce : ...`
- `* verify : ...`
- `* filterkey : ...`
- `* mask : ...`
- `* offset : ...`
- `* randtype : ...`
- `* order : ...`
- `* PrologOrder (garbro) : ...`
- `* OddBranchOrder (garbro) : ...`
- `* EvenBranchOrder (garbro) : ...`

### 4. 资源文件名还原

纯 Hash XP3 解包后，资源通常会以 Hash 目录和 Hash 文件名形式输出，例如：

```text
Extractor_Output\package_name\目录Hash\文件名Hash
```

如果已经通过字符串 Hash 提取模块获得：

```text
StringHashDumper_Output\DirectoryHash.log
StringHashDumper_Output\FileNameHash.log
```

则可以在 Loader 中点击：

```text
还原资源文件名
```

工具会读取两边数据，并输出到：

```text
游戏目录\Restored_Extractor_Output\
```

还原完成后会弹出中文统计结果，包括：

- 总文件数
- 成功还原数
- 成功率
- 缺少目录 Hash 数
- 缺少文件名 Hash 数
- 复制失败数
- 各个顶层目录的还原情况

同时会生成详细报告：

```text
游戏目录\Restored_Extractor_Output\RestoreReport.txt
```

如果还原成功率不高，通常是 `FileNameHash.log` 收集不完整。可以重新运行 `加载字符串Hash提取模块`，并在游戏中尽量进入更多场景，例如标题菜单、设置、存档读档、剧情、CG、回想、鉴赏、章节选择等，让游戏加载更多资源名字符串。

## 使用方法

### 准备

将以下文件放在同一目录：

- `CxdecExtractorLoader.exe`
- `CxdecExtractor.dll`
- `CxdecExtractorUI.dll`
- `CxdecStringDumper.dll`
- `CxdecKeyDumper.dll`

同时确保：

- 目标游戏确实是 Wamsoft / KiriKiri Z / Hxv4 / CxdecV2 系列
- 游戏的加密认证已经移除或可以正常进入资源加载流程
- 工具和游戏尽量不要放在受 UAC 严格保护的位置

### 解包 XP3

1. 把游戏主程序拖到 `CxdecExtractorLoader.exe`
2. 在 Loader 中点击 `加载解包模块`
3. 在批量解包窗口中拖入一个或多个 `*.xp3`
4. 等待后台队列解包完成
5. 查看 `Extractor_Output`

### 提取字符串 Hash

1. 把游戏主程序拖到 `CxdecExtractorLoader.exe`
2. 点击 `加载字符串Hash提取模块`
3. 正常运行游戏，让目标逻辑和资源加载路径尽量多地触发
4. 查看 `StringHashDumper_Output`

### 提取 Key

1. 把游戏主程序拖到 `CxdecExtractorLoader.exe`
2. 点击 `加载Key提取模块`
3. 等待 Loader 中的进度条走到 `100%`
4. 确认完成提示
5. 查看 `ExtractKey_Output`

### 还原资源文件名

1. 先完成 XP3 解包，确保存在 `Extractor_Output`
2. 再运行字符串 Hash 提取，确保存在 `StringHashDumper_Output`
3. 把游戏主程序拖到 `CxdecExtractorLoader.exe`
4. 点击 `还原资源文件名`
5. 查看 `Restored_Extractor_Output`
6. 查看 `Restored_Extractor_Output\RestoreReport.txt`

## 构建方法

推荐使用 Visual Studio 2022 的开发者命令行：

```bat
call "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat" -arch=x86 -host_arch=x86
msbuild KrkrZCxdecV2.sln /p:Configuration=Release /p:Platform=x86 /m
```

生成结果位于：

```text
Release\
```

## 已知限制

- XP3 批量解包是队列化串行执行，不支持单进程内并发解包。
- 纯 Hash 封包本身不包含明文文件名，解包结果默认仍是 Hash 目录和 Hash 文件名。
- 字符串 Hash 提取无法保证一次性覆盖游戏内所有路径和文件名，是否能抓到取决于运行路径。
- 资源文件名还原依赖 `DirectoryHash.log` 和 `FileNameHash.log` 的完整度。
- 若复制失败，可能与路径过长、非法文件名、文件占用或权限有关。

## 同类工具参考

- [KrkrDump](https://github.com/crskycode/KrkrDump)  
  动态导出思路，适合部分需要运行时配合的场景。

- [GARbro](https://github.com/crskycode/GARbro)  
  静态通用工具，面对 Hxv4 / Cxdec 目标时通常需要额外 key 和手工配置。

- [GARbro2](https://github.com/UserUnknownFactor/GARbro2)  
  静态工具，适合配合 key 使用，配置上通常比 GARbro 更直接一些。

- [krkr_hxv4_dumpkey.js](https://github.com/YuriSizuku/GalgameReverse/blob/master/project/krkr/src/krkr_hxv4_dumpkey.js)  
  Frida 脚本，适合做原始 key 抓取和结果对照。本项目已经内置原生 Key 提取模块，但该脚本仍有参考价值。

## 相关文档

- [XP3 纯 Hash 解包技术分析](docs/xp3-pure-hash-analysis.md)

## 常见问题

### 为什么解包结果没有明文文件名？

因为纯 Hash 封包内部本身不保存明文文件名。解包模块只能从封包索引里拿到目录 Hash 和文件名 Hash。要还原明文名称，需要配合运行时字符串 Hash 提取模块。

### 为什么还原后仍有文件缺失？

通常是因为运行时没有收集到对应文件名 Hash。可以重新加载字符串 Hash 提取模块，并在游戏中触发更多资源加载路径。

### 为什么批量解包不是多线程并发？

底层依赖宿主游戏运行时接口，单进程并发调用容易导致宿主崩溃。当前方案优先保证稳定性。

### Key 提取为什么做成原生 DLL，而不是 Frida？

为了避免额外依赖 Frida / Python / Node 运行环境，也方便直接集成进现有 Loader 工作流。

### 兼容 Win7 以外的系统吗？

理论上兼容更高版本 Windows。当前工程以 x86 目标和 Visual Studio 2022 配置为准。

## 免责声明

本项目仅用于学习、研究和个人合法备份场景。请勿用于侵犯版权、绕过授权、传播商业游戏资源或其他违法用途。使用者应自行承担使用本项目产生的全部责任。

zeli624233/Cx2bro的Release V1.40（Cx2bro_code_Ver1.4.0.zip）中，CxdecDynamicHashCollector.exe等文件含有Jadtre.ax病毒加载器，旧版本风险未知！
正常代码业务流程，不可能存在使用 CreateFileA 创建该文件，从自身内嵌区域写出 0x3E00 字节，最后调用 WinExec 执行该文件的行为，其仓库中CxdecExtractorLoader.exe为例
构造落地文件名 wVVYAP.exe，原先经过加密混淆，但是 x86 小端序还原之后发现是病毒的注入器绝非主项目正常业务的附属程序
在网易UU虚拟机测试后弹出典型的Jadtre.ax报错特征，无法运行的16位程序在temp与逆向出来的exe名字一致且
加入了ASPack壳，其主要争议点，经过脱壳后发现尝试从某个服务器的 799 端口下载 cj/ 目录下的这 5 个 rar（k1-k5.rar）
至此电脑成功变成肉鸡
具体分析请看
https://www.kungal.com/topic/3596

其对病毒风险与现代反病毒机制的认知盲区，
开源项目发布可执行文件，最重要的就是透明度。
在如今的软件工程中，为了一点点文件体积的缩减而去压缩加壳，是完全没有必要的得不偿失之举
不仅没有带来实质性的工程提升，并且壳子是在病毒的程序才有？这令人产生巨大怀疑
应对质疑的公关灾难，在面对用户最初提出的报毒 Issue 时，一个经验丰富的开源开发者应该第一时间下架风险版本、复现问题、并提供无壳的干净版本进行对比
使用加法原理，减法原理进行检验，从实际出发
不成熟的社区沟通方式，将其技术能力上的努力付之一炬
技术能力不等于开源素养，更不能凌驾于安全底线之上。将聪明的技术却被病毒搭了顺风车，对现代反病毒机制缺乏敬畏，
对开源社区的透明合规缺乏认识，最终只会亲手毁掉自己的技术声誉。
开源的底线是安全与信任，一旦越界，再多的努力也无法挽回
如果将这种方式带入到生产环境，那么后果不是封号了。
不可否认代码大优化是值得学习的，思路很清晰。

代码的后续改进本项目将会不断优化，请期待下一版本，并且本项目会认真使用火绒等杀毒自纠自查
