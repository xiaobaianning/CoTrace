# iOS ARM64 动态指令追踪工具 — 架构设计

## 目标场景

- **平台**: iOS 越狱设备 (ARM64)
- **核心问题**: 现有工具无法追踪 JIT / 动态生成代码
- **基础**: 在 GumTrace 架构上改进
- **Frida 版本**: 16.x（注意：GumTrace 使用 17.8.3，存在 API 差异）

---

## 一、现有工具不足分析

### 1.1 ATTD-Tracer-QBDI（不可用）

纯 Android 项目，完全不支持 iOS：
- CMakeLists.txt 硬编码 `CMAKE_SYSTEM_NAME=ANDROID`
- QBDI 库只有 Android 版本（`libs/QBDI-aarch64/libQBDI.a`）
- 符号解析基于 ELF（`dl_iterate_phdr()`），iOS 用 Mach-O
- 模块枚举依赖 `/proc/self/maps`，iOS 不存在
- JNI 依赖，无 ObjC/Swift 支持
- 无 PAC（Pointer Authentication）支持
- 不追踪 SIMD/NEON 寄存器

**结论：排除，不考虑。**

### 1.2 GumTrace（可用，但有关键不足）

基于 Frida Gum Stalker，已有 iOS 支持，但在 JIT 场景下失败。

#### 🔴 致命问题：无法追踪动态生成代码

**根因分析**：

Stalker 的 `transform_callback` 对所有流经它的指令都会被调用。问题出在 GumTrace 的白名单过滤逻辑：

```cpp
// GumTrace.cpp:338-360
void GumTrace::transform_callback(...) {
    while (gum_stalker_iterator_next(it, &p_insn)) {
        const std::string *module_name_ptr = self->in_range_module(p_insn->address);
        if (module_name_ptr == nullptr) {
            gum_stalker_iterator_keep(it);  // ← JIT 代码走到这里，被跳过
            continue;
        }
        // 只有命中模块的指令才会被插桩
        gum_stalker_iterator_put_callout(it, callout_callback, callback_ctx, nullptr);
        gum_stalker_iterator_keep(it);
    }
}
```

`in_range_module()` 只检查已加载模块的地址范围。JIT 生成的代码（堆内存、mmap 区域）不在任何模块内，所以永远命中 `nullptr` 分支，不会被追踪。

**关键事实**：Stalker 本身没有模块限制。`gum_stalker_follow_me()` 启动后，所有执行都会经过 Stalker 的 code cache。限制是我们自己在 transformer 里加的。

#### 其他不足

| 问题 | 详情 |
|------|------|
| 仅追踪单线程 | `gum_stalker_follow_me()` 只追踪当前线程 |
| 输出量极大 | 1GB/3秒，文本格式无压缩 |
| 无条件追踪 | 无法按条件过滤，全量记录 |
| PAC 未剥离 | BLR/BR 目标地址可能带 PAC 签名，符号匹配失败 |
| ObjC 不完整 | 缺少 `objc_msgSend_stret`、`objc_msgSendSuper` |
| 无 Swift 支持 | 不追踪 Swift 方法分发 |
| SVC 不可见 | 系统调用内部执行不可追踪 |
| 线程安全 | 50MB buffer 无锁保护 |

---

## 二、问题根因：Stalker 与 JIT 代码

### 2.1 Stalker 工作原理

```
原始代码区域                    Stalker Code Cache
┌──────────────┐              ┌──────────────────┐
│ 0x1000: MOV  │  ──transform──→  MOV + callout   │
│ 0x1004: LDR  │  ──transform──→  LDR + callout   │
│ 0x1008: BL   │  ──transform──→  BL  + callout   │
└──────────────┘              └──────────────────┘
```

Stalker 在指令首次执行时对其进行 transform（重编译到 code cache），在 transform 过程中可以插入 callout（回调函数）。transform 是**惰性的**——只有当执行流到达某个 basic block 时才会 transform 该 block。

### 2.2 为什么 JIT 代码会丢失

GumTrace 在 transform_callback 中做了模块白名单检查：

```
执行流到达 0x2000 (JIT 代码)
    → Stalker 调用 transform_callback
    → in_range_module(0x2000) → nullptr (不在任何模块内)
    → gum_stalker_iterator_keep() → 原始指令直接执行，不插桩
    → 丢失！
```

### 2.3 解决思路

**核心**：在 transformer 中直接判断地址范围，对目标代码插入 callout，对系统库代码直接 keep()。

> ⚠️ **重要修正**（基于代码审阅）：
> 原方案"对所有指令插入 callout，在 callout 内过滤"**不可行**。
> 每次 callout 的实际开销是 50-100ns（Stalker 保存/恢复全量 CPU 上下文 + 函数调用开销），
> 不是估算的 10ns。对系统库每秒数十亿条指令来说，这是 50-200% 的额外开销。
>
> 正确方案：**在 transform_callback 中做地址判断**（与 GumTrace 相同的位置），
> 但将白名单从"仅已知模块"扩展为"已知模块 + 动态 JIT 区域"。
> 不在范围内的指令直接 `gum_stalker_iterator_keep()`，不插入 callout，零开销。

Stalker 的 transform_callback 对所有流经它的指令都会被调用（不管地址在哪），所以：
1. transformer 中检查地址是否在追踪范围（已知模块 + JIT 区域）
2. 在范围内 → 插入 callout
3. 不在范围内 → 直接 keep()，零开销（与 GumTrace 相同）
4. 对系统库使用 `gum_stalker_exclude()` 完全跳过 Stalker 变换

---

## 三、架构设计

### 3.1 整体架构

```
┌──────────────────────────────────────────────────────────────┐
│                        Frida Agent                            │
│                                                               │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │              Code Region Manager                        │  │
│  │                                                         │  │
│  │  静态区域 (启动时枚举):                                  │  │
│  │    libtarget.dylib  [0x1000 - 0x20000]                  │  │
│  │    libcrypto.dylib  [0x30000 - 0x40000]                 │  │
│  │                                                         │  │
│  │  动态区域 (运行时 hook 捕获):                            │  │
│  │    mmap(PROT_EXEC) → 自动加入                           │  │
│  │    mprotect(+PROT_EXEC) → 自动加入                      │  │
│  │                                                         │  │
│  │  数据结构: sorted vector + 无锁原子指针交换              │  │
│  │  查找复杂度: O(log n) 二分查找                          │  │
│  │  线程安全: RCU (Read-Copy-Update)，读路径无锁            │  │
│  └────────────────────────┬────────────────────────────────┘  │
│                           │                                   │
│  ┌────────────────────────▼────────────────────────────────┐  │
│  │              Stalker                                     │  │
│  │                                                         │  │
│  │  系统库: gum_stalker_exclude() 完全跳过                 │  │
│  │    → libobjc.dylib, libsystem_*.dylib 等                │  │
│  │    → 这些库的代码不经过 Stalker 变换                    │  │
│  │                                                         │  │
│  │  transform_callback:                                    │  │
│  │    → 检查地址是否在 CodeRegionManager 范围内            │  │
│  │    → 在范围内: 插入 callout + keep()                   │  │
│  │    → 不在范围内: 直接 keep()，零开销                    │  │
│  │                                                         │  │
│  │  配置:                                                  │  │
│  │    gum_stalker_set_trust_threshold(stalker, 0)          │  │
│  │    // gum_stalker_set_ratio() 仅 Frida 17+，16 不可用   │  │
│  └────────────────────────┬────────────────────────────────┘  │
│                           │                                   │
│  ┌────────────────────────▼────────────────────────────────┐  │
│  │              Callout (仅目标指令)                        │  │
│  │                                                         │  │
│  │  只有目标模块/JIT区域的指令才会到达这里:                 │  │
│  │    1. 寄存器快照 (GPR + SIMD)                          │  │
│  │    2. 内存访问地址计算                                   │  │
│  │    3. 函数调用/返回检测 (含 PAC 剥离)                   │  │
│  │    4. ObjC runtime 拦截 (通过 Interceptor hook)         │  │
│  │    5. 写入每线程独立输出缓冲区                          │  │
│  └────────────────────────┬────────────────────────────────┘  │
│                           │                                   │
│  ┌────────────────────────▼────────────────────────────────┐  │
│  │              Output Engine                              │  │
│  │                                                         │  │
│  │  格式: 二进制 (非文本)                                  │  │
│  │  压缩: LZ4 帧压缩                                      │  │
│  │  缓冲: 每线程独立 ring buffer (16MB)                    │  │
│  │  写入: 后台线程合并 + 异步写入                          │  │
│  │  溢出策略: 阻塞生产者 (保证数据完整性)                  │  │
│  └─────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

### 3.2 模块职责

#### Module 1: Code Region Manager

**职责**：维护所有可执行内存区域的注册表，提供 O(log n) 的地址查询。

**数据结构**：

```
struct CodeRegion {
    uint64_t start;
    uint64_t end;
    RegionType type;      // MODULE, JIT, STACK, HEAP
    std::string name;     // 模块名或 "jit_0x..."
    uint64_t timestamp;   // 创建时间
};

// RCU (Read-Copy-Update) 设计:
// 读路径 (transform_callback 中): 无锁，读取原子指针指向的 sorted vector
// 写路径 (mmap/mprotect hook 中): 复制一份 → 修改 → 原子交换指针
class CodeRegionManager {
    // 原子指针指向排序好的 vector，读路径无锁
    std::atomic<std::vector<CodeRegion>*> regions_;
    
    bool contains(uint64_t addr);           // O(log n) 二分查找，无锁
    void add_region(uint64_t start, uint64_t end, ...);  // 复制+修改+原子交换
    void remove_region(uint64_t start);
};

// 为什么不用 RWLock:
// ARM64 上 pthread_rwlock_rdlock() 即使无竞争也需要 30-80ns
// (原子操作 + 内存屏障)。transform_callback 每条指令都调用，
// 这个开销不可接受。RCU 的读路径只需一次 atomic load (~1ns)。
```

**区域来源**：

| 来源 | 时机 | 实现 |
|------|------|------|
| 用户指定模块 | 启动时 | `Process.findModuleByName()` + `enumerateRanges()` |
| 所有已加载模块 | 启动时 | `Process.enumerateModules()` (排除列表) |
| mmap 分配 | 运行时 | hook `mmap`，检查 `PROT_EXEC` |
| mprotect 变更 | 运行时 | hook `mprotect`，检查 `+PROT_EXEC` |
| mach_vm_allocate | 运行时 | hook `mach_vm_allocate` (iOS Mach 层) |
| dlopen 加载 | 运行时 | hook `dlopen`，枚举新模块范围 |

**mmap hook 实现**：

```javascript
Interceptor.attach(Module.findExportByName(null, 'mmap'), {
    onEnter(args) {
        this.addr = args[0];
        this.size = args[1].toInt32();
        this.prot = args[2].toInt32();
    },
    onLeave(retval) {
        if (this.prot & 0x4) {  // PROT_EXEC = 0x4
            const start = retval.toInt32();
            const end = start + this.size;
            codeRegionManager.addRegion(start, end, RegionType.JIT);
            log(`[JIT] new executable region: 0x${start.toString(16)} - 0x${end.toString(16)}`);
        }
    }
});
```

#### Module 2: Stalker Controller

**职责**：管理 Stalker 的生命周期，配置追踪参数。

```
class StalkerController {
    GumStalker *stalker;
    CodeRegionManager *regionManager;
    
    void start(thread_id);           // gum_stalker_follow_me / gum_stalker_follow
    void stop();                     // gum_stalker_unfollow_me
    void exclude_module(name);       // gum_stalker_exclude (已知系统库)
    
    // transform_callback 作为静态方法
    static void transform_callback(GumStalkerIterator *iterator,
                                    GumStalkerOutput *output,
                                    gpointer user_data);
};
```

**关键改变**（与 GumTrace 对比）：

```cpp
// GumTrace 原版: 仅白名单模块内插桩
const std::string *module_name_ptr = self->in_range_module(p_insn->address);
if (module_name_ptr == nullptr) {
    gum_stalker_iterator_keep(it);  // 跳过
    continue;
}
gum_stalker_iterator_put_callout(it, callout_callback, callback_ctx, nullptr);
gum_stalker_iterator_keep(it);

// 新版: 白名单 + JIT 区域，同样在 transform 中判断
const CodeRegion *region = self->region_manager->find(p_insn->address);
if (region == nullptr) {
    gum_stalker_iterator_keep(it);  // 不在范围内，跳过
    continue;
}
// 在范围内（模块或 JIT 区域），插入 callout
auto callback_ctx = self->callback_context_instance->pull(p_insn, region);
gum_stalker_iterator_put_callout(it, callout_callback, callback_ctx, nullptr);
gum_stalker_iterator_keep(it);
```

**与 GumTrace 的关键区别**：
- GumTrace 的 `in_range_module()` 只检查已加载模块 → 丢失 JIT 代码
- 新版的 `region_manager->find()` 同时检查模块和动态 JIT 区域 → 捕获 JIT 代码
- JIT 区域通过 hook mmap/mprotect 动态添加到 region_manager

**性能考量**：

> ⚠️ **修正**：原方案估算的 callout 开销（~10ns）严重低估。
> 实际开销分析：

| 操作 | 实际开销 |
|------|---------|
| Stalker callout 框架开销（保存/恢复 CPU 上下文） | 30-50ns |
| 函数调用开销（branch + stack frame） | 10-20ns |
| 地址比较（transform 中，无 callout） | ~2ns |
| 地址比较（callout 内，含 RWLock） | 30-80ns |
| 完整追踪逻辑（寄存器+内存+输出） | 100-300ns |

**因此，新版在 transform 中做地址判断（不在范围内直接 keep()），**
**与 GumTrace 性能一致。系统库代码零额外开销。**

| 场景 | GumTrace | 新工具 |
|------|----------|--------|
| 目标模块内 | ~100ns/insn | ~100ns/insn |
| JIT 代码 | ❌ 丢失 | ~100ns/insn |
| 系统库代码 | 0 (transform 跳过) | 0 (exclude + transform 跳过) |
| 整体开销 | 低 | 低（与 GumTrace 相当） |

#### Module 3: Instruction Callback (Callout)

**职责**：对每条目标指令进行记录。

```cpp
void callout_callback(GumCpuContext *cpu_context, gpointer user_data) {
    auto *ctx = (CALLBACK_CTX *)user_data;
    
    // ========== 快速过滤 ==========
    if (!region_manager->contains(cpu_context->pc)) {
        return;  // 非目标指令，直接返回
    }
    
    // ========== 寄存器快照 ==========
    capture_gpr(ctx, cpu_context);      // x0-x28, SP, FP, LR, NZCV
    capture_simd(ctx, cpu_context);     // q0-q31 (128-bit) — 新增
    
    // ========== 内存访问地址 ==========
    compute_memory_address(ctx, cpu_context);  // base + index + disp
    
    // ========== 函数调用检测 ==========
    detect_function_call(ctx, cpu_context);    // BL/BLR/BR/RET
    
    // ========== ObjC/Swift 拦截 ==========
    #if PLATFORM_IOS
    intercept_objc_msgSend(ctx, cpu_context);
    intercept_swift_dispatch(ctx, cpu_context);
    #endif
    
    // ========== 写入输出 ==========
    output_engine->write(ctx);
}
```

**寄存器捕获改进**（相比 GumTrace）：

| 寄存器 | GumTrace | 新工具 | 说明 |
|--------|----------|--------|------|
| x0-x28 | ✅ | ✅ | |
| SP, FP, LR | ✅ | ✅ | |
| NZCV | ✅ | ✅ | |
| q0-q31 (128-bit) | ✅ | ✅ | |
| FPCR, FPSR | ❌ | ❌ | GumCpuContext 不包含此字段，callout 中无法获取 |
| PAC 签名位 | ❌ | ✅ | 通过 gum_strip_code_pointer() 剥离 |

> ⚠️ **修正**：FPCR/FPSR 是 ARM64 系统寄存器，只能通过 MRS 指令访问。
> GumCpuContext 结构体中没有 FPCR/FPSR 字段，callout 机制无法捕获。
> 如需获取，需在目标指令前插入 MRS 指令（inline patch），但这会改变代码行为。

**函数调用检测改进**：

```cpp
// PAC 感知的跳转目标计算
uint64_t strip_pac(uint64_t addr) {
    // iOS ARMv8.3+: 高位是 PAC 签名
    // 用户空间地址通常 < 0x0000800000000000
    // PAC 签名在高位，可以通过指针认证指令或手动剥离
    return addr & 0x0000FFFFFFFFFFFF;  // 简化版，实际需要用 ptrauth API
}

void detect_function_call(CALLBACK_CTX *ctx, GumCpuContext *cpu) {
    uint64_t target = 0;
    switch (ctx->insn_id) {
        case ARM64_INS_BL:
            target = ctx->operands[0].imm;  // 直接调用，无 PAC
            break;
        case ARM64_INS_BLR:
        case ARM64_INS_BR:
            target = get_register_value(ctx->operands[0].reg, cpu);
            target = strip_pac(target);  // ← 新增：剥离 PAC 签名
            break;
        case ARM64_INS_RET:
            target = cpu->lr;
            target = strip_pac(target);  // ← 新增
            break;
    }
    if (target > 0) {
        lookup_and_log_function(ctx, target, cpu);
    }
}
```

#### Module 4: Output Engine

**职责**：高效地将 trace 数据写入磁盘。

**二进制格式设计**：

```
文件头 (64 bytes):
┌────────────────────────────────────────────┐
│ magic: "ITRC" (4 bytes)                    │
│ version: uint32                             │
│ arch: uint32 (ARM64=1)                      │
│ flags: uint32 (has_simd, has_mem, ...)      │
│ module_count: uint32                        │
│ module_table_offset: uint64                 │
│ instruction_count: uint64                   │
│ timestamp_start: uint64                     │
│ reserved: 24 bytes                          │
└────────────────────────────────────────────┘

模块表 (变长):
┌────────────────────────────────────────────┐
│ module[0]: { id: uint16, name_offset: uint32, │
│              base: uint64, size: uint64 }   │
│ module[1]: ...                              │
│ string_table: ...                           │
└────────────────────────────────────────────┘

指令记录 (变长, 每条 8-120 bytes):
┌────────────────────────────────────────────┐
│ type: uint8 (0=insn, 1=call, 2=ret, 3=jit)│
│ module_id: uint16                           │
│ offset: uint32 (模块内偏移)                 │
│ opcode: uint32 (原始指令编码)               │
│ --- 以下按 flags 条件包含 ---               │
│ regs_changed: uint32 (位图)                 │
│ reg_values: uint64[N] (仅变化的寄存器)      │
│ simd_values: uint128[M] (仅使用的 SIMD)     │
│ mem_access: { addr: uint64, type: uint8 }   │
│ func_info: { target: uint64, args: ... }    │
└────────────────────────────────────────────┘
```

**性能对比**：

| 格式 | 每条指令大小 | 1GB 文本对应的大小 |
|------|-------------|-------------------|
| GumTrace 文本 | ~100-200 bytes | 1 GB |
| 二进制 (完整) | ~40-80 bytes | 400-800 MB |
| 二进制 (diff) | ~12-30 bytes | 120-300 MB |
| 二进制 + LZ4 | ~5-15 bytes | 50-150 MB |

**输出架构**：

```
Callout 线程 ──写入──→ 每线程 Ring Buffer (16MB)
                          │
                     后台写入线程 (合并所有线程)
                          │
                     LZ4 压缩
                          │
                     write() 写入文件
```

- 每线程独立 ring buffer，避免锁竞争
- 后台线程异步压缩和写入
- 使用 write() 而非 mmap I/O（保证数据持久化）
- 文件预分配避免碎片

**溢出策略**（⚠️ 关键设计决策）：

```
当 ring buffer 满时:
├── 方案 A: 阻塞生产者 (推荐，保证数据完整性)
│   └── callout 线程等待后台线程腾出空间
│   └── 代价: 追踪线程被暂停，但 trace 数据不丢失
├── 方案 B: 丢弃新数据
│   └── 标记丢弃区间，继续执行
│   └── 代价: trace 不完整，但不阻塞目标进程
└── 方案 C: 动态扩展缓冲区
    └── 分配新的 buffer 段，链表连接
    └── 代价: 内存使用不可预测

推荐方案 A，因为 trace 数据完整性 > 实时性。
阻塞时间取决于后台线程的 LZ4 压缩 + 磁盘写入速度。
16MB buffer 通常可缓冲数秒的 trace 数据。

#### Module 5: ObjC/Swift Runtime Tracing

> ⚠️ **架构说明**：系统库（libobjc.dylib, libswiftCore.dylib 等）被 `gum_stalker_exclude()` 排除，
> Stalker 不会追踪它们的内部执行。
> 因此 ObjC/Swift 追踪使用 **Interceptor hook**（独立于 Stalker），hook 系统库的导出函数入口点。

**ObjC 追踪**（Interceptor hook，独立于 Stalker）：

```
需要 hook 的函数 (通过 Interceptor.attach):
├── objc_msgSend          (普通方法调用)
│   → x0=对象, x1=selector → 解析类名+selector名
├── objc_msgSend_stret    (大结构体返回)      ← 新增
├── objc_msgSendSuper     (super 调用)        ← 新增
├── objc_msgSendSuper_stret                   ← 新增
├── objc_retain / objc_release
│   → 解析对象类名
├── objc_storeStrong / objc_storeWeak
├── NSClassFromString
└── class_addMethod / method_setImplementation (运行时修改检测)

输出格式 (与 Stalker trace 合并):
  [INTERCEPT] objc_msgSend [ClassName selectorName]
  [INTERCEPT] objc_retain <ClassName: 0xaddr>
```

**Swift 追踪**（Interceptor hook）：

```
需要 hook 的函数:
├── swift_retain / swift_release
├── swift_allocObject
├── swift_slowAlloc
├── swift_getGenericMetadata
├── swift_getObjCClassFromMetadata
└── swift_getTypeByMangledNameInContext

Swift 方法分发:
├── 直接调用: 静态函数，通过 BL 调用 → 符号表解析
│   → 在 Stalker callout 中检测 BL 目标
├── VTable 调用: 从对象的 metadata 中读取函数指针
│   → hook swift_allocObject + 解析 metadata layout
└── Witness Table 调用: 协议方法
    → 从 witness table 中读取函数指针
```

#### Module 6: 离线分析工具

**污点分析**（复用 GumTrace 的 `src/taint/`）：
- 需要适配新的二进制格式
- 正向/反向数据流追踪
- 寄存器传播、内存 load/store 传播、NZCV 标志位传播

**反汇编查看器**：
- 将二进制 trace 转换为可读格式
- 支持按地址/模块/函数过滤
- 集成 Trace UI (Tauri + React)

---

## 四、关键技术细节

### 4.1 Stalker 与系统库的策略

**问题**：系统库代码（libsystem_c.dylib, libobjc.dylib 等）经过 Stalker 会有巨大开销。

**解决方案：transform 中过滤 + exclude 排除（双保险）**

```
策略 1: gum_stalker_exclude() 排除已知系统库（Stalker 层面跳过）
  ├── libsystem_kernel.dylib (syscall 入口)
  ├── libdispatch.dylib (GCD)
  ├── libsystem_pthread.dylib
  ├── libsystem_c.dylib, libsystem_m.dylib
  ├── libobjc.dylib (ObjC runtime)
  └── 其他已知不需要的库

  效果: 这些库的代码完全不经过 Stalker 变换，零开销。

策略 2: transform_callback 中地址过滤（对未 exclude 的代码）
  ├── 在范围内 (模块/JIT) → 插入 callout
  └── 不在范围内 → 直接 keep()，零开销

  效果: 防御性措施，处理未被 exclude 覆盖的系统库代码。
```

**系统库函数调用的处理**（⚠️ 重要）：

由于系统库被 exclude，Stalker 不会追踪系统库内部的执行。
但我们仍然需要知道目标代码何时调用了系统库函数。

```
解决方案: Interceptor hook 关键系统函数入口点

需要 hook 的函数:
├── ObjC: objc_msgSend, objc_msgSend_stret, objc_msgSendSuper
│   → 记录 [ClassName selector] 调用
├── C stdlib: malloc, free, mmap, mprotect, open, read, write
│   → 记录参数和返回值
├── Crypto: CC_SHA256, CC_MD5, CCCrypt
│   → 记录输入/输出数据
└── 自定义: 用户指定的任意导出函数

这些 hook 独立于 Stalker，使用 Frida 的 Interceptor.attach()。
即使库被 Stalker exclude，Interceptor 仍然可以 hook 它们的导出函数。
```

**预期性能**：

| 场景 | GumTrace (模块过滤) | 新工具 |
|------|---------------------|--------|
| 目标模块内 | ~100ns/insn | ~100ns/insn |
| JIT 代码 | ❌ 丢失 | ~100ns/insn |
| 系统库代码 | 0 (transform 跳过) | 0 (exclude + transform 跳过) |
| 系统库函数入口 | 不可见 | Interceptor hook 捕获 |
| 整体开销 | 低 | 低（与 GumTrace 相当） |

### 4.2 JIT 代码捕获时机

**场景 1: mmap RWX 一次性完成**
```
mmap(addr, size, PROT_READ|PROT_WRITE|PROT_EXEC, ...)
→ 我们的 hook 捕获，记录区域
→ 但此时代码可能还没写入
→ 第一次执行时，Stalker transform 会处理
→ ✅ 可以追踪
```

**场景 2: mmap RW → 写入代码 → mprotect RX**
```
mmap(addr, size, PROT_READ|PROT_WRITE, ...)
→ 写入机器码
mprotect(addr, size, PROT_READ|PROT_EXEC)
→ 我们的 hook 捕获，记录区域
→ 第一次执行时，Stalker transform 会处理
→ ✅ 可以追踪
```

**场景 3: 代码原地修改（自修改代码）**
```
代码已经在追踪范围内
执行到被修改的指令
→ Stalker 的 code cache 可能还是旧版本
→ 需要 gum_stalker_invalidate(stalker, address)
   使该地址的 code cache 失效
→ Stalker 会重新 transform
→ ✅ 可以追踪（需要主动 invalidate）
```

**场景 4: JIT 代码不在 mmap hook 范围内**
```
使用 vm_allocate / mach_vm_allocate 等非标准 API
→ 如果没 hook 这些 API，会丢失
→ 解决: 全量 Stalker 不依赖 mmap hook
   即使没 hook 到分配，执行时仍会被追踪
→ ✅ 全量 Stalker 天然覆盖
```

### 4.3 多线程追踪

**GumTrace 问题**：只追踪单一线程。

**解决方案**：

```javascript
// 方案 A: 追踪所有线程
Process.enumerateThreads().forEach(thread => {
    stalker.follow(thread.id, { transform, onCallout });
});

// 方案 B: 追踪指定线程集合
function traceThreads(threadIds) {
    threadIds.forEach(id => stalker.follow(id, { transform, onCallout }));
}

// 方案 C: 按需追踪 (新线程自动加入)
Interceptor.attach(Module.findExportByName(null, 'pthread_create'), {
    onLeave(retval) {
        // 新线程创建后自动追踪
        const newThreadId = ...;  // 需要从参数中获取
        setTimeout(() => stalker.follow(newThreadId, ...), 0);
    }
});
```

**线程安全**：

```
问题: 多线程同时写入输出缓冲区
解决:
├── 方案 1: 每线程独立缓冲区 (推荐)
│   └── 每个线程有自己的 ring buffer，后台线程合并写入
├── 方案 2: 无锁队列 (SPSC per thread → MPSC merge)
│   └── 单生产者单消费者队列，合并时用 MPSC
└── 方案 3: 原子操作 + CAS
    └── 适用于简单场景，不适合大量数据
```

### 4.4 PAC (Pointer Authentication) 处理

```cpp
// iOS ARMv8.3+ 所有函数指针和返回地址都经过 PAC 签名
// 高位字节包含认证码，不是真实地址

// 方法 1: 使用 Frida Gum 16 的 ptrauth API（推荐）
// Frida 16 已内置 PAC 支持：
//   gum_query_ptrauth_support()          → GumPtrauthSupport
//   gum_strip_code_pointer(addr)         → 剥离 PAC 签名
//   gum_sign_code_pointer(addr)          → 添加 PAC 签名
//   gum_strip_code_address(addr)         → 剥离地址 PAC
//   gum_sign_code_address(addr, key)     → 签名地址
// 注意: GUM_CPU_PTRAUTH 在 Frida 16 中 = 1 << 5（17 中 = 1 << 6）

// 方法 2: 手动剥离 (用户空间地址通常 < 48-bit)
uint64_t strip_pac(uint64_t addr) {
    // PAC 签名在 bit[47:63]，用户空间地址在 bit[0:47]
    // 简化版: 取低 48 位
    return addr & 0x0000FFFFFFFFFFFF;
}
```

### 4.5 系统调用追踪

**问题**：SVC 指令在 Stalker 之外执行，无法追踪内部。

**缓解方案**：

```
方案 1: Hook libc 包装函数 (推荐)
├── hook open(), read(), write(), mmap(), mprotect(), ioctl()
├── 优点: 可以看到参数和返回值
├── 缺点: 不是所有 syscall 都有 libc 包装
└── 覆盖率: ~80%

方案 2: 使用 DTrace / ktrace (需要内核权限)
├── 优点: 可以追踪所有 syscall
├── 缺点: 需要内核补丁或 CoreTrust 绕过
└── 覆盖率: 100%

方案 3: 组合方案
├── 普通场景: Hook libc 包装函数
├── 关键场景: 使用 kernel patch 追踪 syscall
└── 覆盖率: 可配置
```

---

## 五、构建与部署

### 5.1 项目结构

```
ios-tracer/
├── CMakeLists.txt
├── build_ios.sh
├── libs/
│   ├── FridaGum-iOS-arm64.a
│   └── FridaGum-iOS-arm64.h
├── src/
│   ├── main.cpp                    # 入口，导出 init/run/run
│   ├── Tracer.h/cpp                # 核心追踪引擎
│   ├── CodeRegionManager.h/cpp     # 代码区域管理
│   ├── StalkerController.h/cpp     # Stalker 生命周期
│   ├── CallbackContext.h/cpp       # 指令上下文对象池
│   ├── RegisterCapture.h/cpp       # 寄存器快照 (GPR + SIMD)
│   ├── MemoryAccess.h/cpp          # 内存访问地址计算
│   ├── FunctionDetector.h/cpp      # 函数调用检测 (含 PAC)
│   ├── ObjCTracer.h/cpp            # ObjC runtime 追踪
│   ├── SwiftTracer.h/cpp           # Swift runtime 追踪
│   ├── OutputEngine.h/cpp          # 二进制输出 + LZ4 压缩
│   ├── SyscallHook.h/cpp           # libc syscall hook
│   └── utils.h/cpp                 # 工具函数
├── frida/
│   ├── inject.js                   # Frida 注入脚本
│   └── config.js                   # 配置脚本
├── tools/
│   ├── taint/                      # 污点分析工具
│   ├── disasm/                     # 反汇编查看器
│   └── converter/                  # 二进制→文本转换
└── tests/
    ├── test_jit.cpp                # JIT 追踪测试
    ├── test_selfmod.cpp            # 自修改代码测试
    └── test_multi_thread.cpp       # 多线程测试
```

### 5.2 iOS 构建

```bash
#!/bin/bash
# build_ios.sh

SDK=$(xcrun --sdk iphoneos --show-sdk-path)
CC=$(xcrun --sdk iphoneos -f clang)
CXX=$(xcrun --sdk iphoneos -f clang++)

CFLAGS="-arch arm64 -isysroot $SDK -miphoneos-version-min=14.0 \
        -O2 -fPIC -fvisibility=hidden \
        -DPLATFORM_IOS=1"

$CXX $CFLAGS -c src/*.cpp -Ilibs/ -Isrc/
$CXX -shared -arch arm64 -isysroot $SDK \
     -o build_ios/libIOSTracer.dylib \
     *.o libs/FridaGum-iOS-arm64.a \
     -framework Foundation -framework CoreFoundation \
     -lz  # LZ4 可以静态链接
```

### 5.3 部署与使用

```bash
# 1. 推送到越狱设备
scp build_ios/libIOSTracer.dylib root@<device>:/var/jb/usr/lib/

# 2. Frida 注入
frida -U -f com.target.app -l frida/inject.js

# 3. 拉取 trace
scp root@<device>:/var/mobile/Documents/trace.itrc ./

# 4. 分析
./tools/converter trace.itrc trace.txt    # 转文本
./tools/taint -i trace.itrc -b x0 -l 100  # 污点分析
```

---

## 六、与 GumTrace 的关键差异总结

| 方面 | GumTrace | 新工具 |
|------|----------|--------|
| JIT 追踪 | ❌ 模块白名单过滤 | ✅ 白名单 + 动态 JIT 区域 |
| 多线程 | ❌ 单线程 | ✅ 多线程 + 线程自动发现 |
| 输出格式 | 文本 (1GB/3s) | 二进制 + LZ4 (~50MB/3s) |
| SIMD 寄存器 | ✅ q0-q31 | ✅ q0-q31 |
| FPCR/FPSR | ❌ | ❌ (GumCpuContext 无此字段) |
| PAC 处理 | ❌ | ✅ gum_strip_code_pointer() |
| ObjC | objc_msgSend only | + stret, super, super_stret |
| Swift | ❌ | ✅ Interceptor hook |
| 条件追踪 | ❌ | ✅ 可配置过滤规则 |
| 自修改代码 | ❌ | ✅ gum_stalker_invalidate() |
| 系统调用 | 只记录 SVC | Hook libc 包装函数 |
| 线程安全 | ❌ 无锁 buffer | ✅ 每线程独立缓冲区 + atomic |
| 追踪粒度 | 模块级 | 模块/函数/条件级 |
| 系统库函数调用 | 不可见 | Interceptor hook 捕获 |
| CallbackContext | 非原子 curr_index | std::atomic<int> |
| 模块查找 | O(n) 线性扫描 | O(log n) RCU 无锁查找 |

---

## 七、Frida 16 vs 17 API 差异（重要）

本项目使用 **Frida 16**，而 GumTrace 使用 Frida 17.8.3。以下是关键差异：

### 7.1 Module API：字符串 → 对象（最大变化）

| API | Frida 16 | Frida 17 |
|-----|----------|----------|
| `gum_module_enumerate_symbols()` | `const gchar * module_name` | `GumModule * self` |
| `gum_module_enumerate_dependencies()` | `const gchar * module_name` | `GumModule * self` |
| `gum_module_find_export_by_name()` | `const gchar * module_name` | `GumModule * self` |
| `gum_module_find_symbol_by_name()` | `const gchar * module_name` | `GumModule * self` |
| `gum_process_enumerate_modules()` 回调 | `const GumModuleDetails * details` | `GumModule * module` |
| 模块名获取 | `details->name` | `gum_module_get_name(module)` |
| 模块路径获取 | `details->path` | `gum_module_get_path(module)` |
| 模块范围获取 | `details->range` | `gum_module_get_range(module)` |

### 7.2 仅 Frida 17 存在的 API（不可用）

| API | 替代方案 |
|-----|---------|
| `gum_stalker_set_ratio()` | 不调用，使用默认值 |
| `gum_process_find_module_by_name()` | `gum_process_enumerate_modules()` 遍历查找 |
| `gum_module_get_name/path/range()` | 从 `GumModuleDetails` 结构体直接访问 |
| `gum_module_find_global_export_by_name()` | `gum_process_enumerate_modules()` + `gum_module_find_export_by_name()` 逐模块查找 |

### 7.3 两个版本完全相同的 API（核心 Stalker API）

以下 API 在 Frida 16 和 17 中**签名完全一致**，无需修改：

- `gum_stalker_new()`, `gum_stalker_follow_me()`, `gum_stalker_follow()`
- `gum_stalker_unfollow_me()`, `gum_stalker_unfollow()`
- `gum_stalker_exclude()`, `gum_stalker_set_trust_threshold()`
- `gum_stalker_transformer_make_from_callback()`
- `gum_stalker_iterator_next()`, `gum_stalker_iterator_keep()`
- `gum_stalker_iterator_put_callout()`, `gum_stalker_iterator_get_memory_access()`
- `gum_stalker_invalidate()`
- `GUM_MEMORY_ACCESS_EXCLUSIVE`
- `GumCpuContext` (ARM64) 结构体布局完全一致
- PAC API: `gum_query_ptrauth_support()`, `gum_strip_code_pointer()`, `gum_sign_code_pointer()`
- Code signing: `gum_process_get/set_code_signing_policy()`
- Range: `gum_process_enumerate_ranges()`

### 7.4 GumCpuContext 结构体（两版本一致）

```c
// Frida 16 和 17 中 ARM64 GumCpuContext 完全相同
struct _GumArm64CpuContext {
    guint64 pc;
    guint64 sp;
    guint64 nzcv;
    guint64 x[29];
    guint64 fp;
    guint64 lr;
    GumArm64VectorReg v[32];  // SIMD: q[16], d, s, h, b
};
```

### 7.5 架构影响

**核心结论**：架构设计完全有效。Stalker 核心 API（transformer、iterator、callout）在 Frida 16 中完全可用。需要适配的仅是模块枚举 API，这些只影响：
- 启动时的模块枚举和符号加载
- 运行时的模块名解析

适配工作量很小，主要是将 `GumModule *` 参数改为 `const gchar *` 字符串，以及从 `GumModuleDetails` 结构体直接访问字段。

---

## 八、从 GumTrace 继承的已知 Bug（需修复）

以下是代码审阅发现的 GumTrace 中的 bug，新工具必须修复：

### 8.1 CallbackContext 竞态条件（严重）

```cpp
// GumTrace/src/CallbackContext.cpp:24-27
CALLBACK_CTX* CallbackContext::pull(...) {
    if (curr_index >= CALLBACK_CTX_SIZE) {
        curr_index = 0;
    }
    CALLBACK_CTX *ctx = &list[curr_index++];  // ← 非原子操作！
```

`curr_index` 是普通 `int`。多线程同时调用 `pull()` 会导致：
- 两个线程读到相同的 `curr_index`，获得同一个 slot → 数据损坏
- `curr_index++` 是 read-modify-write，存在数据竞争 → 未定义行为

**修复**：`std::atomic<int> curr_index;` + `curr_index.fetch_add(1) % CALLBACK_CTX_SIZE`

### 8.2 write_reg_list 无边界检查

```cpp
// GumTrace/src/GumTrace.cpp:137,180,252
self->write_reg_list.regs[self->write_reg_list.num++] = op.reg;
```

`REG_LIST` 只有 31 个 slot。某些 NEON 指令可能有超过 31 个寄存器操作数，导致越界写入。

**修复**：添加 `if (write_reg_list.num < 31)` 边界检查。

### 8.3 FUNC_CONTEXT 内嵌 50MB buffer

```cpp
// GumTrace/src/GumTrace.h:29-37
struct FUNC_CONTEXT {
    char info[BUFFER_SIZE];  // BUFFER_SIZE = 50MB !!
    ...
};
```

每个 `FUNC_CONTEXT` 占用 ~50MB。新工具应使用动态分配或池化的小 buffer。

---

## 九、W^X 与代码签名约束（⚠️ 关键）

### 8.1 W^X (Write XOR Execute) 限制

现代 iOS（尤其 iOS 16+）强制 W^X：内存页不能同时可写和可执行。

**对 Stalker 的影响**：
- Stalker 需要分配可执行内存来存放 code cache
- 这需要 `GUM_RWX_ALLOCATIONS_ONLY` 或 `GUM_RWX_FULL` 支持
- Frida 提供 `gum_query_rwx_support()` 查询当前 RWX 能力

```cpp
// 启动时检查
GumRwxSupport rwx = gum_query_rwx_support();
if (rwx == GUM_RWX_NONE) {
    // ❌ Stalker 无法工作，code cache 无法分配
    log("ERROR: RWX not supported, Stalker cannot function");
    return;
}
if (rwx == GUM_RWX_ALLOCATIONS_ONLY) {
    // ⚠️ 只能分配新的 RWX 页，不能修改现有页的权限
    // Stalker 可以工作，但自修改代码追踪可能受限
}
if (rwx == GUM_RWX_FULL) {
    // ✅ 完全支持，无限制
}
```

### 8.2 代码签名与越狱要求

| 越狱类型 | RWX 支持 | Stalker 可用性 |
|---------|---------|---------------|
| Dopamine (rootless, iOS 15-16) | 通常 ALLOCATIONS_ONLY | ✅ 可用 |
| palera1n (rootful, iOS 15-17) | 通常 FULL | ✅ 可用 |
| XinaA15 (iOS 15) | 取决于配置 | ⚠️ 需测试 |
| 越狱 + 无 RWX 补丁 | NONE | ❌ 不可用 |

**`gum_process_set_code_signing_policy(GUM_CODE_SIGNING_OPTIONAL)` 的真实作用**：
- 这是 Frida 内部设置，告诉 Frida 不验证代码签名
- **不**覆盖内核的 W^X 强制执行
- **不**授予 JIT 权限
- 实际效果取决于越狱是否补丁了内核的代码签名检查

### 8.3 JIT 代码的额外约束

iOS 上 JIT 编译需要特殊的 entitlements：
- `com.apple.security.cs.allow-jit` — 允许 JIT 编译
- `com.apple.security.cs.debugger` — 允许调试器附加

越狱设备上这些限制通常被绕过，但：
- 某些 App 的 JIT 可能使用 `MAP_JIT` 标志
- `MAP_JIT` 创建的页面需要在写入和执行之间切换权限
- Stalker 需要正确处理这种页面权限切换

---

## 十、风险与待验证问题

1. **Stalker 对 JIT 代码的 code cache**: Stalker 是否能正确处理动态生成的代码？需要测试
2. **PAC 剥离精度**: `gum_strip_code_pointer()` 是否覆盖所有场景？边缘情况需要测试
3. **自修改代码的 invalidate 时机**: 如何检测代码被修改？可能需要 hook 写入操作
4. **Swift VTable 追踪**: 需要深入理解 Swift runtime 的 metadata layout
5. **LZ4 压缩延迟**: 实时压缩是否会影响追踪性能？
6. **Frida 16 兼容性**: 模块枚举 API 差异需要适配
7. **W^X 支持**: 需要在目标越狱设备上测试 `gum_query_rwx_support()` 返回值
8. **CallbackContext 竞态条件**: 多线程场景下 `curr_index++` 需要改为 `std::atomic<int>::fetch_add()`
9. **write_reg_list 溢出**: 需要添加边界检查（GumTrace 的 bug，新工具需修复）
