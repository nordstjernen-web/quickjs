// clang -g -O1 -fsanitize=address,undefined,fuzzer -o fuzz-regexp fuzz-regexp.c
//
// Fuzz harness for the regexp engine: compiles a pattern taken from the
// start of the input with lre_compile, then runs lre_exec against the
// remainder of the input.  Sizes are bounded so compilation and matching
// stay cheap.
#include "quickjs.h"
#include "quickjs.c"
#include "cutils.h"
#include "libregexp.c"
#include "libunicode.c"
#include "dtoa.c"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Cap the pattern length so we don't spend the whole budget compiling.
#define FUZZ_MAX_PATTERN 1024
// Bound catastrophic backtracking during lre_exec.
#define FUZZ_INTERRUPT_BUDGET 5000000

static int64_t fuzz_counter;

static int fuzz_interrupt(JSRuntime *rt, void *opaque)
{
    return --fuzz_counter <= 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    // Layout: [flags:1][pat_len:1][pattern...][subject...]
    if (len < 2)
        return 0;

    // lre_realloc / lre_check_* (from quickjs.c) expect a JSContext opaque.
    JSRuntime *rt = JS_NewRuntime();
    if (!rt)
        exit(1);
    // lre_check_timeout consults the runtime interrupt handler.
    fuzz_counter = FUZZ_INTERRUPT_BUDGET;
    JS_SetInterruptHandler(rt, fuzz_interrupt, NULL);
    JSContext *ctx = JS_NewContext(rt);
    if (!ctx)
        exit(1);

    int re_flags = buf[0] & 0xff;
    // Keep only flags libregexp understands; UNICODE and UNICODE_SETS are
    // mutually exclusive, prefer UNICODE_SETS if both are set.
    re_flags &= LRE_FLAG_GLOBAL | LRE_FLAG_IGNORECASE | LRE_FLAG_MULTILINE |
                LRE_FLAG_DOTALL | LRE_FLAG_UNICODE | LRE_FLAG_STICKY |
                LRE_FLAG_INDICES | LRE_FLAG_UNICODE_SETS;
    if (re_flags & LRE_FLAG_UNICODE_SETS)
        re_flags &= ~LRE_FLAG_UNICODE;

    size_t pat_len = buf[1];
    if (pat_len > FUZZ_MAX_PATTERN)
        pat_len = FUZZ_MAX_PATTERN;
    if (pat_len > len - 2)
        pat_len = len - 2;
    const uint8_t *subject = &buf[2 + pat_len];
    size_t subject_len = len - 2 - pat_len;

    // lre_compile expects a NUL-terminated pattern (buf[pat_len] == '\0');
    // the JS callers always pass a JS_ToCStringLen2 result.  Copy so the
    // sentinel is present and reject embedded NULs to mirror that contract.
    if (memchr(&buf[2], '\0', pat_len)) {
        JS_FreeContext(ctx);
        JS_FreeRuntime(rt);
        return 0;
    }
    char *pat = malloc(pat_len + 1);
    if (!pat)
        exit(1);
    memcpy(pat, &buf[2], pat_len);
    pat[pat_len] = '\0';

    char error_msg[64];
    int bc_len = 0;
    uint8_t *bc = lre_compile(&bc_len, error_msg, sizeof(error_msg),
                              pat, pat_len, re_flags, ctx);
    free(pat);
    if (bc) {
        int capture_count = lre_get_capture_count(bc);
        uint8_t **capture = NULL;
        if (capture_count > 0) {
            capture = malloc(sizeof(capture[0]) * capture_count * 2);
            if (!capture)
                exit(1);
        }
        // cbuf_type 0: 8-bit subject.  Run at a couple of start indices.
        for (int cindex = 0; cindex <= (int)subject_len; cindex += 1) {
            lre_exec(capture, bc, subject, cindex, (int)subject_len, 0, ctx);
            if (cindex > 64)
                break; // bound the number of starts we probe
        }
        free(capture);
        js_free(ctx, bc);
    }

    JS_FreeContext(ctx);
    JS_FreeRuntime(rt);
    return 0;
}
