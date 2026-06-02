//
// Frida 16/17 兼容层
// 通过 CMake 选项 -DFRIDA_VERSION=16 或 17 控制
//

#ifndef COMPAT_H
#define COMPAT_H

// 默认使用 Frida 17
#ifndef FRIDA_VERSION
#define FRIDA_VERSION 17
#endif

// ============================================================
// 模块枚举回调签名
// ============================================================
#if FRIDA_VERSION >= 17
// Frida 17: GumModule* 基于对象的 API
#define GUM_MODULE_ENUM_CALLBACK(func) \
    gboolean func(GumModule *module, gpointer user_data)
#define GUM_MODULE_ENUM_PARAM  GumModule *GUM_MODULE_ARG,
#define GUM_MODULE_GET_NAME(module)       gum_module_get_name(module)
#define GUM_MODULE_GET_PATH(module)       gum_module_get_path(module)
#define GUM_MODULE_GET_RANGE(module)      gum_module_get_range(module)

#else
// Frida 16: GumModuleDetails* 基于结构体的 API
#define GUM_MODULE_ENUM_CALLBACK(func) \
    gboolean func(const GumModuleDetails *details, gpointer user_data)
#define GUM_MODULE_ENUM_PARAM  const GumModuleDetails *GUM_MODULE_ARG,
#define GUM_MODULE_GET_NAME(details)      (details->name)
#define GUM_MODULE_GET_PATH(details)      (details->path)
#define GUM_MODULE_GET_RANGE(details)     (details->range)

// Frida 16 没有 gum_process_find_module_by_name，需要遍历查找
// 提供一个内联辅助函数
static inline GumModule* gum_process_find_module_by_name_compat(const char *name) {
    struct FindCtx { const char *target; GumModule *result; };
    FindCtx ctx = {name, nullptr};

    gum_process_enumerate_modules(
        +[](const GumModuleDetails *details, gpointer user_data) -> gboolean {
            auto *fc = (FindCtx*)user_data;
            if (details->name && strcmp(details->name, fc->target) == 0) {
                // Frida 16 没有 GumModule*，返回 nullptr 表示找到但无法返回模块对象
                // 调用者需要用 enumerate 方式获取信息
                fc->result = (GumModule*)1;  // 非 nullptr 表示找到
                return FALSE;
            }
            return TRUE;
        }, &ctx);
    return ctx.result;
}

// Frida 16 符号枚举使用字符串模块名
#define gum_module_enumerate_symbols_compat(module_name, callback, data) \
    gum_module_enumerate_symbols(module_name, callback, data)

#define gum_module_enumerate_dependencies_compat(module_name, callback, data) \
    gum_module_enumerate_dependencies(module_name, callback, data)

#define gum_module_find_export_by_name_compat(module_name, symbol) \
    gum_module_find_export_by_name(module_name, symbol)

#define gum_module_find_symbol_by_name_compat(module_name, symbol) \
    gum_module_find_symbol_by_name(module_name, symbol)

#endif

// Frida 17 兼容宏（当使用 Frida 17 时，这些宏直接调用原函数）
#if FRIDA_VERSION >= 17
#define gum_module_enumerate_symbols_compat(module, callback, data) \
    gum_module_enumerate_symbols(module, callback, data)

#define gum_module_enumerate_dependencies_compat(module, callback, data) \
    gum_module_enumerate_dependencies(module, callback, data)

#define gum_module_find_export_by_name_compat(module, symbol) \
    gum_module_find_export_by_name(module, symbol)

#define gum_module_find_symbol_by_name_compat(module, symbol) \
    gum_module_find_symbol_by_name(module, symbol)
#endif

#endif // COMPAT_H
