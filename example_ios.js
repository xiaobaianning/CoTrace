// ============================================================
// CoTrace iOS 使用示例
// ============================================================
// 使用前请修改以下配置:
//   1. traceSoName: dylib 文件名
//   2. dylibSearchPaths: dylib 搜索路径（根据越狱类型）
//   3. targetSo: 要追踪的目标模块名
// ============================================================

// --- 配置区 ---
let traceSoName = 'libGumTrace.dylib'
let targetSo = 'libtarget.dylib'  // 改成你要追踪的模块名

// dylib 搜索路径（按优先级）
let dylibSearchPaths = [
    '/var/jb/var/root/',           // rootless (Dopamine)
    '/var/jb/usr/lib/',            // rootless 备选
    '/usr/lib/',                   // rootful (palera1n)
    '/var/tmp/',                   // 通用备选
    '/tmp/',                       // 最后备选
]

// --- 全局变量 ---
let gumtrace_init = null
let gumtrace_run = null
let gumtrace_unrun = null

// --- 工具函数 ---

function getSandboxPath(filename) {
    try {
        const homePath = ObjC.classes.NSString.stringWithString_("~").stringByExpandingTildeInPath().toString();
        return homePath + '/Documents/' + filename
    } catch (e) {
        console.log('[CoTrace] 获取沙盒路径失败:', e)
        return '/tmp/' + filename
    }
}

function findDylib() {
    // 多种方式查找 dlopen
    let dlopenAddr = Module.findExportByName(null, 'dlopen')
    if (!dlopenAddr) {
        // 从 libdyld 查找
        let libdyld = Process.findModuleByName('libdyld.dylib')
        if (libdyld) dlopenAddr = Module.findExportByName('libdyld.dylib', 'dlopen')
    }
    if (!dlopenAddr) {
        // 从 libSystem 查找
        dlopenAddr = Module.findExportByName('libSystem.B.dylib', 'dlopen')
    }
    if (!dlopenAddr) {
        console.log('[CoTrace] ERROR: cannot find dlopen')
        return null
    }
    console.log('[CoTrace] dlopen at:', dlopenAddr)
    let dlopen = new NativeFunction(dlopenAddr, 'pointer', ['pointer', 'int'])

    for (let path of dylibSearchPaths) {
        let fullPath = path + traceSoName
        console.log('[CoTrace] trying:', fullPath)
        let handle = dlopen(Memory.allocUtf8String(fullPath), 1)  // RTLD_LAZY = 1
        if (handle && !handle.isNull()) {
            console.log('[CoTrace] found dylib at:', fullPath, handle)
            return handle
        }
    }
    console.log('[CoTrace] ERROR: dylib not found in any search path')
    console.log('[CoTrace] searched:', dylibSearchPaths.join(', '))
    return null
}

// --- 核心函数 ---

function loadGumTrace() {
    let soHandle = findDylib()
    if (!soHandle) {
        console.log('[CoTrace] ERROR: failed to load dylib')
        return false
    }

    let dlsymAddr = Module.findExportByName(null, 'dlsym')
    if (!dlsymAddr) {
        let libdyld = Process.findModuleByName('libdyld.dylib')
        if (libdyld) dlsymAddr = Module.findExportByName('libdyld.dylib', 'dlsym')
    }
    if (!dlsymAddr) {
        dlsymAddr = Module.findExportByName('libSystem.B.dylib', 'dlsym')
    }
    if (!dlsymAddr) {
        console.log('[CoTrace] ERROR: cannot find dlsym')
        return false
    }
    let dlsym = new NativeFunction(dlsymAddr, 'pointer', ['pointer', 'pointer'])
    let initAddr = dlsym(soHandle, Memory.allocUtf8String('init'))
    let runAddr = dlsym(soHandle, Memory.allocUtf8String('run'))
    let unrunAddr = dlsym(soHandle, Memory.allocUtf8String('unrun'))

    if (initAddr.isNull() || runAddr.isNull() || unrunAddr.isNull()) {
        console.log('[CoTrace] ERROR: failed to resolve symbols')
        console.log('[CoTrace]   init:', initAddr)
        console.log('[CoTrace]   run:', runAddr)
        console.log('[CoTrace]   unrun:', unrunAddr)
        return false
    }

    gumtrace_init = new NativeFunction(initAddr, 'void', ['pointer', 'pointer', 'int', 'pointer'])
    gumtrace_run = new NativeFunction(runAddr, 'void', [])
    gumtrace_unrun = new NativeFunction(unrunAddr, 'void', [])

    console.log('[CoTrace] dylib loaded successfully')
    return true
}

let _traceStarted = false

function startTrace(moduleName, threadId, mode) {
    if (_traceStarted) {
        console.log('[CoTrace] already started, skipping')
        return
    }
    _traceStarted = true

    moduleName = moduleName || targetSo
    threadId = threadId || 0
    mode = mode || 0

    if (!loadGumTrace()) {
        _traceStarted = false
        return
    }

    let moduleNames = Memory.allocUtf8String(moduleName)
    let outputPath = Memory.allocUtf8String(getSandboxPath('trace.log'))
    let options = Memory.alloc(8)
    options.writeU64(mode)

    console.log('[CoTrace] starting trace:')
    console.log('[CoTrace]   module:', moduleName)
    console.log('[CoTrace]   output:', outputPath)
    console.log('[CoTrace]   thread:', threadId === 0 ? 'current' : threadId)
    console.log('[CoTrace]   mode:', mode === 0 ? 'Stand' : mode === 1 ? 'DEBUG' : 'Stable')

    try {
        gumtrace_init(moduleNames, outputPath, threadId, options)
        console.log('[CoTrace] init() done, calling run()...')
        gumtrace_run()
        console.log('[CoTrace] trace started')
    } catch(e) {
        console.log('[CoTrace] ERROR:', e.message)
        _traceStarted = false
    }
}

function stopTrace() {
    if (gumtrace_unrun) {
        console.log('[CoTrace] stopping trace...')
        gumtrace_unrun()
        _traceStarted = false
        console.log('[CoTrace] trace stopped')
    }
}

// ============================================================
// 使用示例
// ============================================================

// ============================================================
// JIT Hook: 用 Frida JS hook mmap/mprotect，通知 C++ 层
// ============================================================
function setupJitHooks() {
    // hook mmap: 检测 PROT_EXEC 分配
    let mmapAddr = Module.findExportByName(null, 'mmap')
    if (mmapAddr) {
        console.log('[CoTrace] hooking mmap at:', mmapAddr)
        Interceptor.attach(mmapAddr, {
            onEnter(args) {
                this.addr = args[0]
                this.len = args[1].toInt32()
                this.prot = args[2].toInt32()
            },
            onLeave(retval) {
                if (retval.isNull()) return
                if (this.prot & 0x4) {  // PROT_EXEC
                    let start = retval.toInt32()
                    let end = start + this.len
                    console.log('[JIT] mmap detected: 0x' + start.toString(16) + ' - 0x' + end.toString(16) + ' (' + this.len + ' bytes)')
                    // 通知 C++ 层添加区域
                    if (gumtrace_add_region) {
                        gumtrace_add_region(ptr(start), ptr(end))
                    }
                }
            }
        })
    }

    // hook mprotect: 检测 +PROT_EXEC
    let mprotectAddr = Module.findExportByName(null, 'mprotect')
    if (mprotectAddr) {
        console.log('[CoTrace] hooking mprotect at:', mprotectAddr)
        Interceptor.attach(mprotectAddr, {
            onEnter(args) {
                this.addr = args[0]
                this.len = args[1].toInt32()
                this.prot = args[2].toInt32()
            },
            onLeave(retval) {
                if (retval.toInt32() !== 0) return
                if (this.prot & 0x4) {  // PROT_EXEC
                    let start = this.addr.toInt32()
                    let end = start + this.len
                    console.log('[JIT] mprotect detected: 0x' + start.toString(16) + ' - 0x' + end.toString(16))
                    if (gumtrace_add_region) {
                        gumtrace_add_region(ptr(start), ptr(end))
                    }
                }
            }
        })
    }
}

// C++ 导出的 add_region 函数（可选）
let gumtrace_add_region = null

function main() {
    console.log('[CoTrace] iOS example loaded')
    console.log('[CoTrace] target module:', targetSo)

    // 先设置 JIT hooks
    setupJitHooks()

    // 尝试加载 C++ 的 add_region 导出
    try {
        let soHandle = findDylib()
        if (soHandle) {
            let dlsymAddr = Module.findExportByName(null, 'dlsym')
            if (!dlsymAddr) {
                let libdyld = Process.findModuleByName('libdyld.dylib')
                if (libdyld) dlsymAddr = Module.findExportByName('libdyld.dylib', 'dlsym')
            }
            if (dlsymAddr) {
                let dlsym = new NativeFunction(dlsymAddr, 'pointer', ['pointer', 'pointer'])
                let addRegionAddr = dlsym(soHandle, Memory.allocUtf8String('add_jit_region'))
                if (addRegionAddr && !addRegionAddr.isNull()) {
                    gumtrace_add_region = new NativeFunction(addRegionAddr, 'void', ['pointer', 'pointer'])
                    console.log('[CoTrace] add_jit_region exported')
                }
            }
        }
    } catch(e) {
        console.log('[CoTrace] add_jit_region not available:', e.message)
    }

    // 启动追踪
    startTrace()

    // --- 示例 2: hook 目标函数，在其执行期间追踪 ---
    // let targetModule = Process.findModuleByName(targetSo)
    // if (targetModule) {
    //     Interceptor.attach(targetModule.base.add(0x1234), {
    //         onEnter() {
    //             startTrace()
    //             this.tracing = true
    //         },
    //         onLeave() {
    //             if (this.tracing) stopTrace()
    //         }
    //     })
    // }

    // --- 示例 3: 追踪 JIT 代码（指定 JavaScriptCore） ---
    // startTrace('JavaScriptCore')

    // --- 示例 4: 追踪特定线程，DEBUG 模式 ---
    // let threads = Process.enumerateThreads()
    // console.log('[CoTrace] threads:', threads.map(t => t.id).join(', '))
    // startTrace(targetSo, threads[0].id, 1)

    // --- 示例 5: 等待模块加载后追踪 ---
    // Interceptor.attach(Module.findExportByName(null, 'dlopen'), {
    //     onEnter(args) {
    //         this.path = args[0].readUtf8String()
    //     },
    //     onLeave(retval) {
    //         if (this.path && this.path.includes(targetSo)) {
    //             console.log('[CoTrace] target module loaded:', this.path)
    //             startTrace()
    //         }
    //     }
    // })
}

setImmediate(main)
