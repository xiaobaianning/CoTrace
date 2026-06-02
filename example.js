// ============================================================
// CoTrace Android 使用示例
// ============================================================

let traceSoName = 'libGumTrace.so'
let targetSo = 'libtarget.so'  // 改成你要追踪的模块名

let gumtrace_init = null
let gumtrace_run = null
let gumtrace_unrun = null

function loadGumTrace() {
    let dlopen = new NativeFunction(Module.findGlobalExportByName('dlopen'), 'pointer', ['pointer', 'int'])
    let dlsym = new NativeFunction(Module.findGlobalExportByName('dlsym'), 'pointer', ['pointer', 'pointer'])

    let soHandle = dlopen(Memory.allocUtf8String('/data/local/tmp/' + traceSoName), 2)
    if (!soHandle || soHandle.isNull()) {
        console.log('[CoTrace] ERROR: failed to load', traceSoName)
        return false
    }
    console.log('[CoTrace] dylib loaded:', soHandle)

    gumtrace_init = new NativeFunction(dlsym(soHandle, Memory.allocUtf8String('init')), 'void', ['pointer', 'pointer', 'int', 'pointer'])
    gumtrace_run = new NativeFunction(dlsym(soHandle, Memory.allocUtf8String('run')), 'void', [])
    gumtrace_unrun = new NativeFunction(dlsym(soHandle, Memory.allocUtf8String('unrun')), 'void', [])
    return true
}

function startTrace(moduleName, threadId, mode) {
    moduleName = moduleName || targetSo
    threadId = threadId || 0
    mode = mode || 0

    if (!loadGumTrace()) return

    let moduleNames = Memory.allocUtf8String(moduleName)
    let outputPath = Memory.allocUtf8String('/data/data/com.example.app/trace.log')
    let options = Memory.alloc(8)
    options.writeU64(mode)

    console.log('[CoTrace] starting trace:')
    console.log('[CoTrace]   module:', moduleName)
    console.log('[CoTrace]   thread:', threadId === 0 ? 'current' : threadId)
    console.log('[CoTrace]   mode:', mode === 0 ? 'Stand' : mode === 1 ? 'DEBUG' : 'Stable')

    gumtrace_init(moduleNames, outputPath, threadId, options)
    gumtrace_run()
    console.log('[CoTrace] trace started')
}

function stopTrace() {
    if (gumtrace_unrun) {
        console.log('[CoTrace] stopping trace...')
        gumtrace_unrun()
        console.log('[CoTrace] trace stopped')
    }
}

// ============================================================
// 使用示例
// ============================================================

let isTrace = false
function hook() {
    // 等待目标模块加载
    let dlopen_ext = Module.getGlobalExportByName('android_dlopen_ext')
    Interceptor.attach(dlopen_ext, {
        onEnter(args) {
            let pathSo = args[0].readCString()
            if (pathSo.indexOf(targetSo) > -1) {
                this.can = true
            }
        },
        onLeave() {
            if (this.can) {
                console.log('[CoTrace] target module loaded:', targetSo)

                // hook 目标函数，在其执行期间进行追踪
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
            }
        }
    })

    // 或者直接启动追踪
    // startTrace()
}

setImmediate(hook)
