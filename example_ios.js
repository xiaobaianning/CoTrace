let traceSoName = 'libGumTrace.dylib'
let targetSo = 'libtarget.dylib'

let gumtrace_init = null
let gumtrace_run = null
let gumtrace_unrun = null

function loadGumTrace() {
    let dlopen = new NativeFunction(Module.findGlobalExportByName('dlopen'), 'pointer', ['pointer', 'int'])
    let dlsym = new NativeFunction(Module.findGlobalExportByName('dlsym'), 'pointer', ['pointer', 'pointer'])

    let soHandle = dlopen(Memory.allocUtf8String('/var/jb/var/root/' + traceSoName), 2)
    console.log('GumTrace loaded:', soHandle)

    gumtrace_init = new NativeFunction(dlsym(soHandle, Memory.allocUtf8String('init')), 'void', ['pointer', 'pointer', 'int', 'pointer'])
    gumtrace_run = new NativeFunction(dlsym(soHandle, Memory.allocUtf8String('run')), 'void', [])
    gumtrace_unrun = new NativeFunction(dlsym(soHandle, Memory.allocUtf8String('unrun')), 'void', [])
}


function getSandboxPath(filename) {
    try {
        const homePath = ObjC.classes.NSString.stringWithString_("~").stringByExpandingTildeInPath().toString();
        console.log('trace file:', homePath + '/Documents/' + filename);
        return homePath + '/Documents/' + filename;
    } catch (e) {
        console.log('获取沙盒路径失败:', e);
        return '/tmp/' + filename
    }
}

// ============================================================
// 模式 1: 追踪指定模块（标准用法）
// ============================================================
function startTrace() {
    loadGumTrace()

    let moduleNames = Memory.allocUtf8String(targetSo)
    let outputPath = Memory.allocUtf8String(getSandboxPath('trace.log'))
    let threadId = 0   // 0 = 当前线程
    let options = Memory.alloc(8)

    // 0 = Stand 模式
    // 1 = DEBUG 模式（高频刷写，实时查看）
    // 2 = Stable 模式（更安全，但较慢）
    options.writeU64(0)

    console.log('start trace')

    gumtrace_init(moduleNames, outputPath, threadId, options)
    gumtrace_run()
}

function stopTrace() {
    console.log('stop trace')
    gumtrace_unrun()
}

// ============================================================
// 模式 2: 追踪 JIT 代码（自动检测 mmap/mprotect）
// ============================================================
// CoTrace 会自动 hook mmap/mprotect，当检测到 PROT_EXEC 的
// 内存分配时，自动将其加入追踪范围。
//
// 使用方法：只需指定一个初始模块，JIT 区域会在运行时自动捕获。
// 例如追踪使用 JavaScriptCore 的应用：
//
//   let moduleNames = Memory.allocUtf8String('JavaScriptCore')
//
// 或追踪使用自定义 VM 的应用：
//
//   let moduleNames = Memory.allocUtf8String('libvm.dylib')
//
// JIT 生成的代码会自动被追踪，无需手动指定地址。

// ============================================================
// 使用示例
// ============================================================

let isTrace = false
function hook() {

    // 示例 1: hook 目标函数，在其执行期间进行追踪
    let targetModule = Process.findModuleByName(targetSo)
    if (targetModule) {
        Interceptor.attach(targetModule.base.add(0x1234), {
            onEnter() {
                if (isTrace === false) {
                    isTrace = true
                    startTrace()
                    this.tracing = true
                }
            },
            onLeave() {
                if (this.tracing) {
                    stopTrace()
                }
            }
        })
    }

    // 示例 2: 直接启动全量追踪（包含 JIT 代码）
    // startTrace()

    // 示例 3: 追踪特定线程
    // loadGumTrace()
    // let moduleNames = Memory.allocUtf8String(targetSo)
    // let outputPath = Memory.allocUtf8String(getSandboxPath('trace.log'))
    // let threadId = Process.enumerateThreads()[0].id  // 指定线程 ID
    // let options = Memory.alloc(8)
    // options.writeU64(1)  // DEBUG 模式
    // gumtrace_init(moduleNames, outputPath, threadId, options)
    // gumtrace_run()
}

setImmediate(hook)
