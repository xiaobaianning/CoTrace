//
// Created by lidongyooo on 2026/2/6.
//

#include "CallbackContext.h"

#include <utility>


CallbackContext *CallbackContext::get_instance() {
    static CallbackContext instance;
    return &instance;
}


CallbackContext::CallbackContext() {
    list = (CALLBACK_CTX*)calloc(CALLBACK_CTX_SIZE, sizeof(CALLBACK_CTX));
}

CallbackContext::~CallbackContext() {
    free(list);
}

CALLBACK_CTX* CallbackContext::pull(const cs_insn* _instruction, const char* module_name, uint64_t module_base) {
    // 原子操作获取索引，修复多线程竞态条件
    int idx = curr_index.fetch_add(1, std::memory_order_relaxed) % CALLBACK_CTX_SIZE;

    CALLBACK_CTX *ctx = &list[idx];
    ctx->module_name = module_name;
    ctx->module_base = module_base;
    memcpy(&ctx->instruction, _instruction, sizeof(cs_insn));
    if (_instruction->detail) {
        memcpy(&ctx->instruction_detail, _instruction->detail, sizeof(cs_detail));
        ctx->instruction.detail = &ctx->instruction_detail;
    } else {
        ctx->instruction.detail = nullptr;
    }

    return ctx;
}


