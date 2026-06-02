
# CoTrace — iOS ARM64 动态指令追踪工具

基于 Frida Gum (Stalker) 引擎的 iOS ARM64 真机动态指令追踪工具，支持 JIT 代码追踪。

> **核心特性：JIT 代码追踪** — 自动检测并追踪动态生成的代码（mmap/mprotect PROT_EXEC），无需手动指定 JIT 区域。

## 致谢
-  [Trace UI](https://github.com/imj01y/trace-ui) - 本项目官方指定的 trace 分析工具。高性能 ARM64 执行 trace 可视化分析工具。基于 Tauri 2 + React 构建的桌面应用，专为安全研究员设计，支持千万行或亿行级大规模 trace 的流畅浏览、函数调用树折叠、反向污点追踪、内存/寄存器实时查看等功能。Trace Ul 与 CoTrace 深度适配，是在分析 trace 日志时的得力助手。感谢 [@imj01y](https://github.com/imj01y) 的开源贡献!

## 功能概述

CoTrace 以 dylib 形式注入目标进程，对指定模块进行指令级别的动态追踪，并将完整的执行轨迹写入日志文件。

### 核心功能

- **指令级追踪** — 逐条记录 ARM64 指令的执行，包括模块名、绝对地址、相对偏移、助记符和操作数
- **寄存器快照** — 记录每条指令执行时的寄存器读写值（通用寄存器 x0-x28、SIMD 寄存器 q/d/s/h/b、SP、FP、LR、NZCV）
- **内存访问追踪** — 记录内存读写的目标地址（mem_r / mem_w），支持基址 + 索引 + 偏移的复合寻址计算
- **函数调用拦截** — 自动识别 BL/BLR/BR/B 指令的跳转目标，匹配已知符号后打印函数参数和返回值
- **PAC 指针剥离** — 自动剥离 ARM64 PAC 签名，正确解析间接调用/跳转目标地址
- **JIT 代码追踪** — 自动检测 mmap/mprotect 分配的可执行内存，追踪动态生成的代码
- **ObjC 追踪** — 拦截 objc_msgSend，解析类名、selector，打印 NSDictionary/NSArray/NSString/NSData/NSNumber 等 ObjC 对象
- **系统调用追踪** — 拦截 SVC 指令，根据系统调用号解析函数名

### 污点分析工具

项目附带一个独立的离线污点分析工具（`src/taint/`），可对 CoTrace 生成的日志进行正向/反向数据流追踪：

- **正向追踪** — 从指定寄存器或内存地址出发，追踪数据如何被传播
- **反向追踪** — 从指定寄存器或内存地址出发，反向追溯数据来源
- 支持寄存器间传播、寄存器与内存间的 load/store 传播、NZCV 标志位传播
- 输出匹配的指令及每步的污点快照

## 日志格式

每行指令记录的格式如下：

```
[模块名] 0x绝对地址!0x相对偏移 助记符 操作数; 寄存器名=值 mem_r=地址 mem_w=地址
```

示例：

```
[libtarget.dylib] 0x104c7c!0xc7c ldr x0, [x1, #0x10]; x1=0x104c7c0000 mem_r=0x104c7c0010
-> x0=0x12345678
call func: strcmp(0x104c7c0010, 0x104c7c0600)
args0: hello
args1: world
ret: 0xffffffffffffffff
```

## 构建

### 环境要求

- CMake >= 3.10
- Xcode + iphoneos SDK（arm64，最低 iOS 12.0）
- Frida Gum 静态库（已包含在 `libs/` 目录）

### 构建

```bash
./build_ios.sh
# 产物: build_ios/libGumTrace.dylib
```

### 构建污点分析工具

```bash
cd src/taint
mkdir -p build && cd build
cmake ..
cmake --build .
# 产物: taint_tracker
```

## API

CoTrace 编译为 dylib，导出以下 C 接口：

### `init(module_names, trace_file_path, thread_id, options)`

初始化追踪器。

| 参数 | 类型 | 说明 |
|---|---|---|
| `module_names` | `const char*` | 要追踪的模块名，多个用逗号分隔（如 `"libtarget.dylib,libcrypto.dylib"`） |
| `trace_file_path` | `char*` | 日志输出文件路径 |
| `thread_id` | `int` | 要追踪的线程 ID（0 表示追踪当前线程） |
| `options` | `GUM_OPTIONS*` | 选项指针，写入 `uint64_t` 模式值 |

### `run()`

启动追踪。会创建一个后台线程定期刷写日志文件。

### `unrun()`

停止追踪，刷写并关闭日志文件。

## 部署与使用

### 1. 推送到越狱设备

```bash
# rootless 越狱 (Dopamine)
scp build_ios/libGumTrace.dylib root@<device_ip>:/var/jb/var/root/

# rootful 越狱 (palera1n)
scp build_ios/libGumTrace.dylib root@<device_ip>:/usr/lib/
```

### 2. 编辑 Frida 脚本

编辑 `example_ios.js` 中的配置：

```javascript
// dylib 文件名
let traceSoName = 'libGumTrace.dylib'
// 要追踪的模块名
let targetSo = 'libtarget.dylib'  // 改成实际的模块名
```

### 3. 运行

```bash
frida -U -f com.target.app -l example_ios.js
```

### 4. 拉取日志

```bash
# 日志在应用沙盒的 Documents 目录下
scp root@<device_ip>:/var/mobile/Containers/Data/Application/<UUID>/Documents/trace.log ./
```

### 追踪模式

```javascript
// 直接追踪（最简单）
startTrace()

// 追踪指定模块
startTrace('JavaScriptCore')

// 追踪特定线程 + DEBUG 模式
startTrace('libtarget.dylib', 12345, 1)

// 等待模块加载后追踪（hook dlopen）
// 见 example_ios.js 中的示例 5
```

### 模式说明

| 模式 | 值 | 说明 |
|------|---|------|
| Stand | 0 | 默认模式，每 20 秒刷写一次 |
| DEBUG | 1 | 高频刷写（每 20 条指令），实时查看 |
| Stable | 2 | 更安全，信任阈值 2，但较慢 |

> **注意事项：**
> - 需要越狱设备（Dopamine / palera1n 等）
> - Frida 服务需要在设备上运行（`frida-server` 16+）
> - JIT 追踪会自动检测 mmap/mprotect 分配的可执行内存
> - PAC 指针会自动剥离，无需手动处理

## 调试日志

CoTrace 内置了详细的调试日志，用于排查问题：

```bash
frida -U -f com.target.app -l example_ios.js 2>&1 | grep -E "\[CoTrace\]|\[JIT\]|\[CALL\]|\[PAC\]|\[Stalker\]|\[Buffer\]|\[RegionManager\]"
```

### 日志标签说明

| 标签 | 说明 |
|------|------|
| `[CoTrace init()]` | 初始化参数：模块名、输出路径、线程 ID、模式 |
| `[CoTrace run()/unrun()]` | 生命周期：追踪启动/停止 |
| `RWX support` | RWX 内存支持检查结果 |
| `[RegionManager]` | JIT 区域添加/更新事件 |
| `[JIT]` | 首次命中 JIT 区域时打印指令地址 |
| `[CALL]` | 函数调用目标地址（首次出现时） |
| `[PAC]` | PAC 指针剥离事件（BLR/BR 目标） |
| `[Buffer]` | 缓冲区刷写到磁盘 |
| `[Stalker]` | Stalker follow/unfollow 状态、追踪的模块和区域列表 |

### 常见问题排查

**Q: JIT 代码没有被追踪**
```
检查日志中是否有:
  [JIT] mprotect detected: ...  → mmap/mprotect hook 是否工作
  [JIT] instrumenting: ...      → Stalker 是否在 JIT 区域插入了 callout
如果没有 [JIT] 日志，说明目标进程没有通过标准 mmap/mprotect 分配可执行内存。
```

**Q: 函数调用没有被拦截**
```
检查日志中是否有:
  [CALL] 0x... -> 0x... known_func=0  → 跳转目标不在符号表中
  [PAC] BLR stripped: 0x... -> 0x...  → PAC 签名被剥离
如果 known_func=0，说明目标函数没有符号信息（strip 后的二进制）。
```

**Q: 缓冲区溢出**
```
检查日志中是否有:
  [Buffer] flushing ... bytes to disk  → 正常刷写
如果频繁出现，说明 trace 数据量过大，考虑缩小追踪范围。
```

## 污点分析工具使用

### 命令行

```bash
# 正向追踪：从第 100 行的 x0 寄存器开始追踪数据流向
./taint_tracker -i trace.log -o result.log -f x0 -l 100

# 反向追踪：从第 500 行的 x0 寄存器反向追溯数据来源
./taint_tracker -i trace.log -o result.log -b x0 -l 500

# 追踪内存地址
./taint_tracker -i trace.log -o result.log -f mem:0x1000 -l 100

# 按相对地址定位起始位置
./taint_tracker -i trace.log -o result.log -f x0 -a 0x1890

# 按字节偏移定位起始位置
./taint_tracker -i trace.log -o result.log -b x0 -p 1048576
```

### 010 Editor 插件

项目提供了 010 Editor 脚本 [TaintTracker.1sc](src/taint/TaintTracker.1sc)，可以在 010 Editor 中直接对 trace 日志进行交互式污点分析。

## 项目结构

```
CoTrace/
├── CMakeLists.txt              # 主构建脚本
├── build_ios.sh                # iOS 构建脚本
├── example_ios.js              # Frida 使用示例
├── docs/
│   └── architecture.md         # 架构设计文档
├── libs/                       # Frida Gum 静态库和头文件
│   ├── FridaGum-IOS-17.8.3.h
│   └── FridaGum-IOS-17.8.3-fix.a
└── src/
    ├── main.cpp                # 入口，导出 init/run/unrun + mmap/mprotect/dlopen hook
    ├── GumTrace.h/cpp          # 核心追踪引擎（Stalker、CodeRegionManager、JIT 追踪）
    ├── CallbackContext.h/cpp   # 指令上下文对象池（原子操作，线程安全）
    ├── FuncPrinter.h/cpp       # 函数调用参数/返回值打印（ObjC 对象解析）
    ├── Utils.h/cpp             # 工具函数（寄存器值读取、hexdump、字符串格式化）
    ├── platform.h              # 平台检测宏
    └── taint/                  # 离线污点分析工具
        ├── CMakeLists.txt
        ├── main.cpp            # 命令行入口
        ├── TraceParser.h/cpp   # 日志解析器（零分配设计）
        ├── TaintEngine.h/cpp   # 污点传播引擎（正向/反向）
        └── TaintTracker.1sc    # 010 Editor 污点分析脚本
```

## 内置函数识别

CoTrace 内置了对常见库函数参数的自动解析：

| 类别 | 函数 |
|---|---|
| 字符串操作 | `strlen`, `strcmp`, `strncmp`, `strcpy`, `strcat`, `strstr`, `strdup` 等 |
| 内存操作 | `memcpy`, `memmove`, `memset`, `memcmp`, `memmem` 等 |
| 文件操作 | `open`, `openat`, `read`, `write`, `fopen`, `close` 等 |
| 内存分配 | `malloc`, `calloc`, `realloc`, `free` |
| 内存映射 | `mmap`, `mprotect` |
| 动态链接 | `dlopen`, `dlsym`, `dlclose` |
| 格式化 | `sprintf`, `snprintf`, `sscanf` |
| 系统 | `syscall`, `sysconf` |
| ObjC | `objc_msgSend`, `objc_retain`, `objc_release`, `NSClassFromString` 等 |

## 技术细节

- 基于 Frida Gum Stalker 进行代码插桩，使用 `gum_stalker_iterator_put_callout` 在每条指令前插入回调
- 使用 Capstone 反汇编引擎解析 ARM64 指令的操作数和访问类型
- 自动排除系统模块，仅追踪用户指定的目标模块
- **JIT 代码追踪**：hook mmap/mprotect 检测 PROT_EXEC 内存分配，自动加入追踪范围
- **PAC 指针剥离**：使用 `gum_strip_code_pointer()` 自动剥离 ARM64 PAC 签名
- **RCU 无锁区域查找**：CodeRegionManager 使用原子指针 + 二分查找，读路径零锁开销
- **线程安全**：CallbackContext 使用 `std::atomic<int>` 修复多线程竞态条件
- 跳过原子指令（LSE、独占加载/存储）以避免 Stalker 插桩导致的死锁
- 使用 50MB 内存缓冲区减少文件 I/O 次数，提升追踪性能
- 污点分析工具采用零分配解析设计，可高效处理 GB 级日志文件

## CI/CD

项目使用 GitHub Actions 自动构建。每次 push 到 `main` 分支会自动触发构建。

- 构建产物：`CoTrace-ios-arm64.dylib`
- 下载地址：[Releases](https://github.com/xiaobaianning/CoTrace/releases/tag/latest)
