#ifndef COMPILER_H
#define COMPILER_H

#include <linux/bpf.h>
typedef unsigned long long u64;

#define __section(n) __attribute__((section(n), used))
#define __bpf_section __section("bpf")

#define __maybe_unused __attribute__((__unused__))

#define __use_bpf_helper(name, arg, func) \
	static u64 (*name)(arg) = (void *)func

static __attribute__((__format__(printf, 1, 3))) __maybe_unused void
(*trace_printk)(const char *fmt, int fmt_size, ...) = (void *) BPF_FUNC_trace_printk;

#define printk(fmt, ...)                       \
	({                                         \
		const char ____fmt[] = fmt;            \
		trace_printk(____fmt, sizeof(____fmt), \
		##__VA_ARGS__);                        \
	})

#endif
