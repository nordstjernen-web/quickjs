// clang -g -O1 -fsanitize=address,undefined,fuzzer -o fuzz-eval fuzz-eval.c
//
// Fuzz harness for the parser + interpreter: treats the input as UTF-8
// JavaScript source and runs it through JS_Eval with strict time and
// memory budgets so a single input can neither hang nor OOM the fuzzer.
#include "quickjs.h"
#include "quickjs.c"
#include "cutils.h"
#include "libregexp.c"
#include "libunicode.c"
#include "dtoa.c"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Wall-clock budget per input, in milliseconds.
#define FUZZ_DEADLINE_MS 1000
// Bytecode-instruction style interrupt: bail out after this many calls.
#define FUZZ_INTERRUPT_BUDGET 1000000

typedef struct {
    int64_t deadline_ms;    // monotonic deadline
    int64_t counter;        // remaining interrupt budget
} FuzzInterruptState;

static int64_t fuzz_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int fuzz_interrupt(JSRuntime *rt, void *opaque)
{
    FuzzInterruptState *st = opaque;
    if (--st->counter <= 0)
        return 1;
    // Only consult the clock occasionally to keep the handler cheap.
    if ((st->counter & 0x3ff) == 0 && fuzz_now_ms() >= st->deadline_ms)
        return 1;
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    if (!len)
        return 0;
    // The input must be a valid NUL-terminated C string for JS_Eval.
    if (memchr(buf, '\0', len))
        return 0;

    JSRuntime *rt = JS_NewRuntime();
    if (!rt)
        exit(1);
    // 64 MiB heap and 256 KiB native stack keep pathological inputs bounded.
    JS_SetMemoryLimit(rt, 64 * 1024 * 1024);
    JS_SetMaxStackSize(rt, 256 * 1024);

    FuzzInterruptState st = {
        .deadline_ms = fuzz_now_ms() + FUZZ_DEADLINE_MS,
        .counter = FUZZ_INTERRUPT_BUDGET,
    };
    JS_SetInterruptHandler(rt, fuzz_interrupt, &st);

    JSContext *ctx = JS_NewContext(rt);
    if (!ctx)
        exit(1);

    char *src = malloc(len + 1);
    if (!src)
        exit(1);
    memcpy(src, buf, len);
    src[len] = '\0';

    int flags = JS_EVAL_TYPE_GLOBAL;
    JSValue val = JS_Eval(ctx, src, len, "<fuzz>", flags);
    free(src);

    // Drain any pending jobs (promises, FinalizationRegistry callbacks) so we
    // also exercise that path; the interrupt handler bounds the work.
    if (!JS_IsException(val)) {
        JSContext *ctx1;
        int err;
        for (;;) {
            err = JS_ExecutePendingJob(rt, &ctx1);
            if (err <= 0)
                break;
        }
    }

    JS_FreeValue(ctx, val);
    JS_FreeContext(ctx);
    JS_FreeRuntime(rt);
    return 0;
}
