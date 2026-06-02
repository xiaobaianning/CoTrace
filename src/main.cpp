//
// Created by lidongyooo on 2026/2/5.
//

// ============================================================
// Frida 16 vs 17 API 差异说明
// ============================================================
//
// 本文件当前使用 Frida 17 API。切换到 Frida 16 需要以下修改:
//
// 1. 回调签名:
//    Frida 17: gboolean callback(GumModule *module, gpointer user_data)
//    Frida 16: gboolean callback(const GumModuleDetails *details, gpointer user_data)
//
// 2. 模块信息获取:
//    Frida 17: gum_module_get_name(module), gum_module_get_path(module), gum_module_get_range(module)
//    Frida 16: details->name, details->path, details->range
//
// 3. 模块查找:
//    Frida 17: gum_process_find_module_by_name(name) → GumModule*
//    Frida 16: 不存在，需用 gum_process_enumerate_modules() 遍历
//
// 4. 符号枚举:
//    Frida 17: gum_module_enumerate_symbols(GumModule*, callback, data)
//    Frida 16: gum_module_enumerate_symbols(const gchar* module_name, callback, data)
//
// 5. Stalker 配置:
//    Frida 17: gum_stalker_set_ratio(stalker, ratio)
//    Frida 16: 不存在此 API
//
// 6. 全局符号查找:
//    Frida 17: gum_module_find_global_export_by_name(name)
//    Frida 16: 不存在，需遍历所有模块的 gum_module_find_export_by_name()
//
// 7. GumCpuFeatures:
//    Frida 16: GUM_CPU_PTRAUTH = 1 << 5
//    Frida 17: GUM_CPU_PTRAUTH = 1 << 6
//
// ============================================================

#include "GumTrace.h"
#include "Utils.h"
#include <sys/mman.h>  // PROT_EXEC, MAP_FAILED

gboolean module_symbols_cb(const GumSymbolDetails * details, gpointer user_data) {
    auto *instance = GumTrace::get_instance();
    if (details && details->name && details->address && details->section != nullptr &&
        (details->section->protection & GUM_PAGE_READ)) {
        instance->func_maps[details->address] = details->name;
    }

    // if (details->is_global) {
    //     size_t global_addr = gum_module_find_global_export_by_name(details->name);
    //     if (global_addr > 0) {
    //         instance->func_maps[global_addr] = details->name;
    //     }
    // }

    return true;
}

gboolean module_dependency_cb (const GumDependencyDetails * details, gpointer user_data) {
    // Frida 16 适配: gum_process_find_module_by_name() 不存在
    // 需要使用 gum_process_enumerate_modules() 遍历查找
    // 当前代码使用 Frida 17 API，切换到 Frida 16 时需改为:
    //
    // struct FindCtx { const char *name; GumModule *result; };
    // FindCtx ctx = {details->name, nullptr};
    // gum_process_enumerate_modules(+[](const GumModuleDetails *d, gpointer ud) -> gboolean {
    //     auto *fc = (FindCtx*)ud;
    //     if (strcmp(d->name, fc->name) == 0) { fc->found_range = d->range; return FALSE; }
    //     return TRUE;
    // }, &ctx);
    // 然后用 gum_module_enumerate_symbols(details->name, ...) 代替

    auto gum_module = gum_process_find_module_by_name(details->name);
    if (gum_module != nullptr) {
        gum_module_enumerate_symbols(gum_module, module_symbols_cb, nullptr);
    }
    return true;
}

gboolean on_range_found(const GumRangeDetails *details, gpointer user_data) {
    auto instance = GumTrace::get_instance();

    RangeInfo info;
    info.base = (uintptr_t) details->range->base_address;
    info.size = (uintptr_t) details->range->size;
    info.end = info.base + info.size;

    if (details->file) {
        info.file_path = details->file->path;
    } else {
        info.file_path = "maybe heap";
    }

    instance->safa_ranges.push_back(info);
    return TRUE;
}

gboolean module_enumerate (GumModule * module, gpointer user_data) {
    auto instance = GumTrace::get_instance();
    const char *module_name = gum_module_get_name(module);

    if (instance->modules.count(module_name) > 0) {
        return true;
    }

#if PLATFORM_ANDROID
    auto module_path = gum_module_get_path(module);
    auto gum_module_range = gum_module_get_range(module);

    LOGE("module_enumerate %s %s %lx %lx", module_name, module_path, gum_module_range->base_address, gum_module_range->size);

    if (strncmp(module_path, "/system/", 8) == 0 || strncmp(module_path, "/system_ext/", 12) == 0  ||
        strncmp(module_path, "/apex/", 6) == 0 || strncmp(module_path, "/vendor/", 8) == 0 ||
        strstr(module_path, "libGumTrace.so") != nullptr || strstr(module_path, ".odex") != nullptr ||
        strstr(module_path, "memfd") != nullptr) {
        gum_stalker_exclude(instance->_stalker, gum_module_range);
    } else {
        if (instance->modules.count(module_name) == 0) {
            auto &module_map = instance->modules[module_name];
            module_map ["base"] = gum_module_range->base_address;
            module_map ["size"] = gum_module_range->size;
        }
    }

    return true;

#else

    if (instance->modules.count(module_name) == 0) {
        gum_stalker_exclude(instance->_stalker, gum_module_get_range(module));
    }
    return true;

#endif
}

extern "C" __attribute__((visibility("default")))
void init(const char *module_names, char *trace_file_path, int thread_id, GUM_OPTIONS* options) {

    LOGE("=== CoTrace init() called ===");
    LOGE("  module_names: %s", module_names ? module_names : "(null)");
    LOGE("  trace_file_path: %s", trace_file_path ? trace_file_path : "(null)");
    LOGE("  thread_id: %d", thread_id);
    LOGE("  options: %p", options);

    LOGE("[Step 1] gum_init()...");
    gum_init();
    LOGE("[Step 1] gum_init() done");

    LOGE("[Step 2] gum_process_get_code_signing_policy()...");
    auto code_signing_policy = gum_process_get_code_signing_policy();
    LOGE("Gum code signing policy before init: %s",
         gum_code_signing_policy_to_string(code_signing_policy));
#if PLATFORM_IOS
    if (code_signing_policy != GUM_CODE_SIGNING_OPTIONAL) {
        gum_process_set_code_signing_policy(GUM_CODE_SIGNING_OPTIONAL);
        LOGE("Gum code signing policy forced to: %s",
             gum_code_signing_policy_to_string(gum_process_get_code_signing_policy()));
    }
#endif

    LOGE("[Step 3] GumTrace::get_instance()...");
    GumTrace *instance = GumTrace::get_instance();
    LOGE("[Step 3] instance: %p", instance);

    LOGE("[Step 4] memcpy options...");
    if (options) {
        memcpy(&instance->options, options, sizeof(GUM_OPTIONS));
    } else {
        instance->options.mode = 0;
    }
    LOGE("[Step 4] options mode: %llu", instance->options.mode);

    // 检查 RWX 支持（仅日志，不阻断）
    GumRwxSupport rwx_support = gum_query_rwx_support();
    LOGE("RWX support: %s",
         rwx_support == GUM_RWX_FULL ? "FULL" :
         rwx_support == GUM_RWX_ALLOCATIONS_ONLY ? "ALLOCATIONS_ONLY" : "NONE");
    if (rwx_support == GUM_RWX_NONE) {
        LOGE("RWX detection says NONE, but continuing anyway (jailbreak may still support it)");
    }

    LOGE("[Step 5] gum_stalker_new()...");
    instance->_stalker = gum_stalker_new();
    if (!instance->_stalker) {
        LOGE("[Step 5] ERROR: gum_stalker_new() returned null!");
        return;
    }
    LOGE("[Step 5] stalker: %p", instance->_stalker);

    LOGE("[Step 6] gum_stalker_set_trust_threshold(0)...");
    gum_stalker_set_trust_threshold(instance->_stalker, 0);
    LOGE("[Step 6] done");

    if (instance->options.mode == GUM_OPTIONS_MODE_STABLE) {
        gum_process_enumerate_ranges(GUM_PAGE_RW, on_range_found, nullptr);

        std::sort(instance->safa_ranges.begin(), instance->safa_ranges.end(),
          [](const RangeInfo &a, const RangeInfo &b) { return a.base < b.base; });
        gum_stalker_set_trust_threshold(instance->_stalker, 2);
        // gum_stalker_set_ratio(instance->_stalker, 5);  // Frida 16 不可用
    }

    auto module_names_vector = Utils::str_split(module_names, ',');
    for (const auto &module_name: module_names_vector) {
        auto *gum_module = gum_process_find_module_by_name(module_name.c_str());
        if (gum_module == nullptr) {
            LOGE("module not found: %s", module_name.c_str());
            continue;
        }
        auto &module_map = instance->modules[module_name];
        gum_module_enumerate_symbols(gum_module, module_symbols_cb, nullptr);
        gum_module_enumerate_dependencies(gum_module, module_dependency_cb, nullptr);
        auto *gum_module_range = gum_module_get_range(gum_module);
        module_map["base"] = gum_module_range->base_address;
        module_map["size"] = gum_module_range->size;
    }

    LOGE("[Step 7] enumerating modules...");
    gum_process_enumerate_modules(module_enumerate, nullptr);
    LOGE("[Step 7] done, %zu modules tracked", instance->modules.size());

    // ============================================================
    // Hook mmap/mprotect 检测 JIT 代码区域
    // ============================================================

    LOGE("[Step 8] interceptor hooks deferred to run()");
    // Hooks are set up in run() after Stalker is fully initialized

    size_t path_len = strlen(trace_file_path);
    if (path_len >= sizeof(instance->trace_file_path)) {
        path_len = sizeof(instance->trace_file_path) - 1;
    }
    memcpy(instance->trace_file_path, trace_file_path, path_len);
    instance->trace_file_path[path_len] = '\0';
    instance->trace_thread_id = thread_id;
    instance->trace_file = std::ofstream(instance->trace_file_path, std::ios::out | std::ios::trunc);

    LOGE("[Step 9] loading syscall names...");
    for (const auto& svc_name : svc_names) {
        auto svc_name_vector = Utils::str_split(svc_name, ' ');
        instance->svc_func_maps[std::stoi(svc_name_vector.at(1))] = svc_name_vector.at(0);
    }
    LOGE("[Step 9] done, %zu syscall names loaded", instance->svc_func_maps.size());

#if PLATFORM_ANDROID
    auto libart_module = gum_process_find_module_by_name("libart.so");
    GumAddress JNI_GetCreatedJavaVMs_addr = gum_module_find_symbol_by_name(libart_module, "JNI_GetCreatedJavaVMs");
    if (JNI_GetCreatedJavaVMs_addr == 0) {
        JNI_GetCreatedJavaVMs_addr = gum_module_find_export_by_name(libart_module, "JNI_GetCreatedJavaVMs");
    }
    if (JNI_GetCreatedJavaVMs_addr == 0) {
        JNI_GetCreatedJavaVMs_addr = gum_module_find_global_export_by_name("JNI_GetCreatedJavaVMs");
    }
    if (JNI_GetCreatedJavaVMs_addr == 0) {
        LOGE("未找到JNI_GetCreatedJavaVMs符号");
    } else {
        typedef jint (*JNI_GetCreatedJavaVMs_t)(JavaVM**, jsize, jsize*);
        auto *jni_get_created_vms = reinterpret_cast<JNI_GetCreatedJavaVMs_t>(JNI_GetCreatedJavaVMs_addr);
        jsize vm_count = 1;
        auto **vms = new JavaVM*[vm_count];
        jint result = jni_get_created_vms(vms, vm_count, &vm_count);
        if (result == JNI_OK && vm_count > 0) {
            instance->java_vm = vms[0];
            LOGE("成功获取JavaVM: %p", instance->java_vm);
        } else {
            LOGE("获取JavaVM失败，错误码: %d", result);
        }

        delete[] vms;
    }
#    endif

    LOGE("=== CoTrace init() complete ===");
}

void* thread_function(void* arg) {
    GumTrace *instance = GumTrace::get_instance();
    size_t last_size = 0;

    while (true) {
        if (instance->trace_file.is_open()) {
            if (!(instance->options.mode == GUM_OPTIONS_MODE_DEBUG)) {
                struct stat stat_buf;
                int ret = stat(instance->trace_file_path, &stat_buf);

                if (ret == 0) {
                    off_t growth = stat_buf.st_size - last_size;
                    off_t growth_mb = growth / (1024 * 1024);
                    off_t size_gb = stat_buf.st_size / (1024 * 1024 * 1024);

                    LOGE("每20秒新增：%ldMB 当前文件大小：%ldGB",
                         growth_mb, size_gb);
                    last_size = stat_buf.st_size;
                } else {
                    LOGE("stat 失败，错误码：%d，错误信息：%s",
                         errno, strerror(errno));
                    LOGE("文件路径：%s", instance->trace_file_path);
                }
            }

            instance->trace_file.flush();
        } else {
            LOGE("trace_file 未打开");
            break;
        }

        if (instance->options.mode == GUM_OPTIONS_MODE_DEBUG) {
            usleep(1000);
        } else {
            usleep(1000 * 1000 * 20);
        }
    }

    return nullptr;
}


// JIT hook 设置函数（延迟到 run() 中调用）
static void setup_jit_hooks() {
    LOGE("[JIT Hooks] setting up mmap/mprotect/dlopen hooks...");

    // mmap hook
    auto mmap_addr = gum_module_find_export_by_name(NULL, "mmap");
    LOGE("[JIT Hooks] mmap: 0x%lx", (uintptr_t)mmap_addr);
    if (mmap_addr != 0) {
        static auto original_mmap = (gpointer(*)(uintptr_t, size_t, int, int, int, off_t))mmap_addr;
        GumInterceptor *interceptor = gum_interceptor_obtain();
        gum_interceptor_begin_transaction(interceptor);
        gum_interceptor_replace_fast(interceptor, GSIZE_TO_POINTER(mmap_addr),
            (gpointer) +[](uintptr_t addr, size_t length, int prot, int flags, int fd, off_t offset) -> gpointer {
                gpointer result = original_mmap(addr, length, prot, flags, fd, offset);
                if (result != MAP_FAILED && (prot & PROT_EXEC)) {
                    auto *rm = CodeRegionManager::get_instance();
                    char name[64];
                    snprintf(name, sizeof(name), "jit_mmap_0x%llx", (unsigned long long)(uintptr_t)result);
                    rm->add_region((uintptr_t)result, (uintptr_t)result + length, RegionType::JIT, name);
                    LOGE("[JIT] mmap: %s [0x%llx - 0x%llx]", name,
                         (unsigned long long)(uintptr_t)result, (unsigned long long)(uintptr_t)result + length);
                }
                return result;
            }, nullptr);
        gum_interceptor_end_transaction(interceptor);
        LOGE("[JIT Hooks] mmap hook installed");
    }

    // mprotect hook
    auto mprotect_addr = gum_module_find_export_by_name(NULL, "mprotect");
    LOGE("[JIT Hooks] mprotect: 0x%lx", (uintptr_t)mprotect_addr);
    if (mprotect_addr != 0) {
        static auto original_mprotect = (int(*)(gpointer, size_t, int))mprotect_addr;
        GumInterceptor *interceptor = gum_interceptor_obtain();
        gum_interceptor_begin_transaction(interceptor);
        gum_interceptor_replace_fast(interceptor, GSIZE_TO_POINTER(mprotect_addr),
            (gpointer) +[](gpointer addr, size_t length, int prot) -> int {
                int result = original_mprotect(addr, length, prot);
                if (result == 0 && (prot & PROT_EXEC)) {
                    auto *rm = CodeRegionManager::get_instance();
                    char name[64];
                    snprintf(name, sizeof(name), "jit_mprot_0x%llx", (unsigned long long)(uintptr_t)addr);
                    rm->add_region((uintptr_t)addr, (uintptr_t)addr + length, RegionType::JIT, name);
                    LOGE("[JIT] mprotect: %s [0x%llx - 0x%llx]", name,
                         (unsigned long long)(uintptr_t)addr, (unsigned long long)(uintptr_t)addr + length);
                }
                return result;
            }, nullptr);
        gum_interceptor_end_transaction(interceptor);
        LOGE("[JIT Hooks] mprotect hook installed");
    }

    LOGE("[JIT Hooks] done");
}

extern "C" __attribute__((visibility("default")))
void run() {
    LOGE("=== CoTrace run() called ===");

    // 设置 JIT hooks（在 Stalker 初始化之后）
    setup_jit_hooks();

    pthread_t thread1;
    pthread_create(&thread1, NULL, thread_function, nullptr);
    LOGE("Background flush thread created");

    GumTrace *instance = GumTrace::get_instance();
    instance->follow();

    LOGE("=== CoTrace run() done ===");
}

extern "C" __attribute__((visibility("default")))
void unrun() {
    LOGE("=== CoTrace unrun() called ===");
    GumTrace *instance = GumTrace::get_instance();
    instance->unfollow();
    LOGE("=== CoTrace unrun() done ===");
}

int main() {
    printf("xxx %p", main);
}
