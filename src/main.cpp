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
#include "compat.h"
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
#if FRIDA_VERSION >= 17
    auto gum_module = gum_process_find_module_by_name(details->name);
    if (gum_module != nullptr) {
        gum_module_enumerate_symbols(gum_module, module_symbols_cb, nullptr);
    }
#else
    // Frida 16: 直接用模块名枚举符号
    gum_module_enumerate_symbols(details->name, module_symbols_cb, nullptr);
#endif
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

#if FRIDA_VERSION >= 17
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
#else
// Frida 16 版本
gboolean module_enumerate (const GumModuleDetails * details, gpointer user_data) {
    auto instance = GumTrace::get_instance();
    const char *module_name = details->name;

    if (instance->modules.count(module_name) > 0) {
        return true;
    }

#if PLATFORM_ANDROID
    auto module_path = details->path;
    auto gum_module_range = details->range;

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
        gum_stalker_exclude(instance->_stalker, details->range);
    }
    return true;

#endif
}
#endif

extern "C" __attribute__((visibility("default")))
void init(const char *module_names, char *trace_file_path, int thread_id, GUM_OPTIONS* options) {

    gum_init();
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

    GumTrace *instance = GumTrace::get_instance();
    memcpy(&instance->options, options, sizeof(GUM_OPTIONS));

    // 检查 RWX 支持
    GumRwxSupport rwx_support = gum_query_rwx_support();
    LOGE("RWX support: %s",
         rwx_support == GUM_RWX_FULL ? "FULL" :
         rwx_support == GUM_RWX_ALLOCATIONS_ONLY ? "ALLOCATIONS_ONLY" : "NONE");
    if (rwx_support == GUM_RWX_NONE) {
        LOGE("WARNING: RWX not supported. Stalker may not work correctly.");
    }

    instance->_stalker = gum_stalker_new();
    gum_stalker_set_trust_threshold(instance->_stalker, 0);
    // 注意: gum_stalker_set_ratio() 仅 Frida 17+ 可用，Frida 16 中不存在
    if (instance->options.mode == GUM_OPTIONS_MODE_STABLE) {
        gum_process_enumerate_ranges(GUM_PAGE_RW, on_range_found, nullptr);

        std::sort(instance->safa_ranges.begin(), instance->safa_ranges.end(),
          [](const RangeInfo &a, const RangeInfo &b) { return a.base < b.base; });
        gum_stalker_set_trust_threshold(instance->_stalker, 2);
        // gum_stalker_set_ratio(instance->_stalker, 5);  // Frida 16 不可用
    }

    auto module_names_vector = Utils::str_split(module_names, ',');
    for (const auto &module_name: module_names_vector) {
#if FRIDA_VERSION >= 17
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
#else
        // Frida 16: 使用字符串模块名
        gum_module_enumerate_symbols(module_name.c_str(), module_symbols_cb, nullptr);
        gum_module_enumerate_dependencies(module_name.c_str(), module_dependency_cb, nullptr);
        // 通过 enumerate 查找模块范围
        struct ModFindCtx { const char *name; GumMemoryRange range; bool found; };
        ModFindCtx mctx = {module_name.c_str(), {0, 0}, false};
        gum_process_enumerate_modules(
            +[](const GumModuleDetails *d, gpointer ud) -> gboolean {
                auto *fc = (ModFindCtx*)ud;
                if (d->name && strcmp(d->name, fc->name) == 0) {
                    fc->range = *d->range;
                    fc->found = true;
                    return FALSE;
                }
                return TRUE;
            }, &mctx);
        if (mctx.found) {
            auto &module_map = instance->modules[module_name];
            module_map["base"] = mctx.range.base_address;
            module_map["size"] = mctx.range.size;
        } else {
            LOGE("module not found: %s", module_name.c_str());
        }
#endif
    }

    gum_process_enumerate_modules(module_enumerate, nullptr);

    // ============================================================
    // Hook mmap/mprotect 检测 JIT 代码区域
    // ============================================================

    // mmap hook: 检测带 PROT_EXEC 的内存分配
    auto mmap_addr = gum_module_find_export_by_name(NULL, "mmap");
    if (mmap_addr != 0) {
        // 保存原始函数指针
        static auto original_mmap = (gpointer(*)(uintptr_t, size_t, int, int, int, off_t))mmap_addr;

        GumInterceptor *mmap_interceptor = gum_interceptor_obtain();
        gum_interceptor_begin_transaction(mmap_interceptor);
        gum_interceptor_replace_fast(mmap_interceptor, GSIZE_TO_POINTER(mmap_addr),
            (gpointer) +[](uintptr_t addr, size_t length, int prot, int flags, int fd, off_t offset) -> gpointer {
                gpointer result = original_mmap(addr, length, prot, flags, fd, offset);

                if (result != MAP_FAILED && (prot & PROT_EXEC)) {
                    auto *rm = CodeRegionManager::get_instance();
                    char name[64];
                    snprintf(name, sizeof(name), "jit_mmap_0x%llx", (unsigned long long)(uintptr_t)result);
                    rm->add_region((uintptr_t)result, (uintptr_t)result + length,
                                   RegionType::JIT, name);
                    LOGE("[JIT] mmap detected: %s [0x%llx - 0x%llx] (%zu bytes)",
                         name, (unsigned long long)(uintptr_t)result,
                         (unsigned long long)(uintptr_t)result + length, length);
                }
                return result;
            }, nullptr);
        gum_interceptor_end_transaction(mmap_interceptor);
    }

    // mprotect hook: 检测权限变更为 PROT_EXEC
    auto mprotect_addr = gum_module_find_export_by_name(NULL, "mprotect");
    if (mprotect_addr != 0) {
        static auto original_mprotect = (int(*)(gpointer, size_t, int))mprotect_addr;

        GumInterceptor *mprotect_interceptor = gum_interceptor_obtain();
        gum_interceptor_begin_transaction(mprotect_interceptor);
        gum_interceptor_replace_fast(mprotect_interceptor, GSIZE_TO_POINTER(mprotect_addr),
            (gpointer) +[](gpointer addr, size_t length, int prot) -> int {
                int result = original_mprotect(addr, length, prot);

                if (result == 0 && (prot & PROT_EXEC)) {
                    auto *rm = CodeRegionManager::get_instance();
                    char name[64];
                    snprintf(name, sizeof(name), "jit_mprot_0x%llx", (unsigned long long)(uintptr_t)addr);
                    rm->add_region((uintptr_t)addr, (uintptr_t)addr + length,
                                   RegionType::JIT, name);
                    LOGE("[JIT] mprotect detected: %s [0x%llx - 0x%llx] (%zu bytes)",
                         name, (unsigned long long)(uintptr_t)addr,
                         (unsigned long long)(uintptr_t)addr + length, length);
                }
                return result;
            }, nullptr);
        gum_interceptor_end_transaction(mprotect_interceptor);
    }

    // dlopen hook: 检测新加载的模块
    auto dlopen_addr = gum_module_find_export_by_name(NULL, "dlopen");
    if (dlopen_addr != 0) {
        static auto original_dlopen = (gpointer(*)(const char*, int))dlopen_addr;

        GumInterceptor *dlopen_interceptor = gum_interceptor_obtain();
        gum_interceptor_begin_transaction(dlopen_interceptor);
        gum_interceptor_replace_fast(dlopen_interceptor, GSIZE_TO_POINTER(dlopen_addr),
            (gpointer) +[](const char *path, int flags) -> gpointer {
                gpointer result = original_dlopen(path, flags);

                if (result != nullptr && path != nullptr) {
                    const char *mod_name = strrchr(path, '/');
                    if (mod_name) mod_name++; else mod_name = path;

                    // 查找新加载的模块并加入追踪范围
                    struct FindCtx { const char *target; GumMemoryRange range; bool found; };
                    FindCtx ctx = {mod_name, {0, 0}, false};

                    gum_process_enumerate_modules(
                        +[](GUM_MODULE_ENUM_PARAM
                            gpointer user_data) -> gboolean {
                            auto *fc = (FindCtx*)user_data;
                            const char *name = GUM_MODULE_GET_NAME(GUM_MODULE_ARG);
                            if (name && strcmp(name, fc->target) == 0) {
                                auto *range = GUM_MODULE_GET_RANGE(GUM_MODULE_ARG);
                                if (range) {
                                    fc->range = *range;
                                    fc->found = true;
                                }
                                return FALSE;
                            }
                            return TRUE;
                        }, &ctx);

                    if (ctx.found) {
                        auto *rm = CodeRegionManager::get_instance();
                        rm->add_region(ctx.range.base_address,
                                      ctx.range.base_address + ctx.range.size,
                                      RegionType::MODULE, mod_name);
                        LOGE("[MODULE] dlopen detected: %s [0x%llx - 0x%llx]",
                             mod_name,
                             (unsigned long long)ctx.range.base_address,
                             (unsigned long long)(ctx.range.base_address + ctx.range.size));
                    }
                }
                return result;
            }, nullptr);
        gum_interceptor_end_transaction(dlopen_interceptor);
    }

    size_t path_len = strlen(trace_file_path);
    if (path_len >= sizeof(instance->trace_file_path)) {
        path_len = sizeof(instance->trace_file_path) - 1;
    }
    memcpy(instance->trace_file_path, trace_file_path, path_len);
    instance->trace_file_path[path_len] = '\0';
    instance->trace_thread_id = thread_id;
    instance->trace_file = std::ofstream(instance->trace_file_path, std::ios::out | std::ios::trunc);

    for (const auto& svc_name : svc_names) {
        auto svc_name_vector = Utils::str_split(svc_name, ' ');
        instance->svc_func_maps[std::stoi(svc_name_vector.at(1))] = svc_name_vector.at(0);
    }

#if PLATFORM_ANDROID
#if FRIDA_VERSION >= 17
    auto libart_module = gum_process_find_module_by_name("libart.so");
    GumAddress JNI_GetCreatedJavaVMs_addr = gum_module_find_symbol_by_name(libart_module, "JNI_GetCreatedJavaVMs");
    if (JNI_GetCreatedJavaVMs_addr == 0) {
        JNI_GetCreatedJavaVMs_addr = gum_module_find_export_by_name(libart_module, "JNI_GetCreatedJavaVMs");
    }
    if (JNI_GetCreatedJavaVMs_addr == 0) {
        JNI_GetCreatedJavaVMs_addr = gum_module_find_global_export_by_name("JNI_GetCreatedJavaVMs");
    }
#else
    // Frida 16: 使用字符串模块名
    GumAddress JNI_GetCreatedJavaVMs_addr = gum_module_find_symbol_by_name("libart.so", "JNI_GetCreatedJavaVMs");
    if (JNI_GetCreatedJavaVMs_addr == 0) {
        JNI_GetCreatedJavaVMs_addr = gum_module_find_export_by_name("libart.so", "JNI_GetCreatedJavaVMs");
    }
#endif
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


extern "C" __attribute__((visibility("default")))
void run() {

    pthread_t thread1;
    pthread_create(&thread1, NULL, thread_function, nullptr);

    GumTrace *instance = GumTrace::get_instance();
    instance->follow();
}

extern "C" __attribute__((visibility("default")))
void unrun() {
    GumTrace *instance = GumTrace::get_instance();
    instance->unfollow();
}

int main() {
    printf("xxx %p", main);
}
