//
// Created by lidongyooo on 2026/2/6.
//

#ifndef GUMTRACE_GUMTRACE_H
#define GUMTRACE_GUMTRACE_H

#include "Utils.h"
#include "CallbackContext.h"
#include <mutex>
#include <atomic>
#include <algorithm>  // std::sort

struct REG_LIST {
    int num = 0;
    arm64_reg regs[31] = {};

    void add(arm64_reg reg) {
        if (num < 31) {  // 边界检查，防止越界写入
            regs[num++] = reg;
        }
    }
};


typedef enum {
    GUM_OPTIONS_MODE_Stand = 0,
    GUM_OPTIONS_MODE_DEBUG,
    GUM_OPTIONS_MODE_STABLE
} GUM_OPTIONS_MODE;

struct GUM_OPTIONS {
    uint64_t mode;
};

#define BUFFER_SIZE (1024 * 1024 * 50)
#define FUNC_INFO_SIZE (1024 * 4)  // 函数信息缓冲区从 50MB 缩减到 4KB

struct FUNC_CONTEXT {
    uint64_t address;
    const char* name;
    char info[FUNC_INFO_SIZE];  // 修复: 原来是 BUFFER_SIZE (50MB)，导致每个 FUNC_CONTEXT 占 50MB
    int info_n;
    bool call;
    bool is_jni;
    GumCpuContext cpu_context;
};

struct RangeInfo {
    uintptr_t base;
    uintptr_t size;
    uintptr_t end;
    std::string file_path;
};

// ============================================================
// CodeRegionManager: 管理可执行内存区域（模块 + JIT）
// 使用 RCU 设计：读路径无锁，写路径复制+原子交换
// ============================================================

enum class RegionType {
    MODULE,     // 已加载的模块
    JIT,        // 动态生成的代码 (mmap/mprotect)
    CUSTOM      // 用户自定义区域
};

struct CodeRegion {
    uintptr_t start;
    uintptr_t end;
    RegionType type;
    std::string name;

    bool contains(uintptr_t addr) const {
        return addr >= start && addr < end;
    }
};

class CodeRegionManager {
public:
    static CodeRegionManager* get_instance();

    // 检查地址是否在已知区域内 (O(log n) 二分查找)
    // 读路径无锁，使用 atomic 指针
    bool contains(uintptr_t addr) const;

    // 查找地址所在的区域，返回区域指针（可能为 nullptr）
    const CodeRegion* find(uintptr_t addr) const;

    // 添加新区域（写路径，复制+原子交换）
    void add_region(uintptr_t start, uintptr_t end, RegionType type, const std::string& name);

    // 移除区域
    void remove_region(uintptr_t start);

    // 获取当前区域列表的快照
    std::vector<CodeRegion> get_regions() const;

private:
    CodeRegionManager();
    ~CodeRegionManager();

    // RCU: 原子指针指向排序好的 vector
    // 读路径: atomic load + binary search
    // 写路径: copy → modify → atomic swap
    std::atomic<std::vector<CodeRegion>*> regions_{nullptr};

    // 写路径互斥锁（仅写操作需要）
    std::mutex write_mutex_;

    CodeRegionManager(const CodeRegionManager&) = delete;
    CodeRegionManager& operator=(const CodeRegionManager&) = delete;
};

class GumTrace {
public:
    static GumTrace *get_instance();
    std::map<std::string, std::map<std::string, std::size_t>> modules;
    char trace_file_path[256];
    std::ofstream trace_file;
    int trace_thread_id;
    int trace_flush = 0;
    std::unordered_map<size_t, std::string> func_maps;
    FUNC_CONTEXT last_func_context = {};

    GumStalker* _stalker;
    GumStalkerTransformer* _transformer;

    CallbackContext* callback_context_instance;
    CodeRegionManager* region_manager;  // 新增: JIT 区域管理器

    static void transform_callback(GumStalkerIterator *iterator, GumStalkerOutput *output, gpointer user_data);
    const std::string* in_range_module(size_t address);
    bool in_trace_range(uintptr_t address);  // 新增: 检查模块+JIT区域
    const RangeInfo* find_range_by_address(uintptr_t addr);
    const std::map<std::string, std::size_t>& get_module_by_name(const std::string &module_name);
    void follow();
    void unfollow();

    static void callout_callback(GumCpuContext *cpu_context, gpointer user_data);

    char buffer[BUFFER_SIZE] = {};
    int buffer_offset = 0;
    REG_LIST write_reg_list;

    struct CachedModule {
        const std::string* name;
        size_t base;
        size_t end;
    } last_module_cache;

    GUM_OPTIONS options;
    std::vector<RangeInfo> safa_ranges;

    std::unordered_map<size_t, std::string> svc_func_maps;
    std::unordered_map<size_t, std::string> func_fds;

    uintptr_t atomic_addr = 0;
    int atomic_width = 0;
    uintptr_t atomic_counter = 10;

#if PLATFORM_ANDROID
    JNIEnv *get_run_time_env();


    JavaVM *java_vm = nullptr;
    JNIEnv *jni_env = nullptr;
    bool jni_env_init = false;
    std::unordered_map<size_t, std::string> jni_func_maps;
    std::unordered_map<size_t, std::string> jni_classes;
    std::unordered_map<size_t, std::string> jni_methods;
    std::unordered_map<size_t, std::string> jni_methods_classes;
#    endif



private:
    GumTrace();

    ~GumTrace();

    GumTrace(const GumTrace &) = delete;

    GumTrace &operator=(const GumTrace &) = delete;
};


#endif //GUMTRACE_GUMTRACE_H