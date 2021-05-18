CC        := clang
CFLAGS    += -Wall -Werror -std=c11
LLVMFLAGS += -O2 -target bpf -g -emit-llvm -c

LLC       := llc
LLFLAGS   := -march=bpf -mcpu=v3 -mattr=dwarfris -filetype=obj
OBJCOPY   := llvm-objcopy

BPFSRCS   := bpf_sk_filter.c
BPFLLVM   := $(BPFSRCS:.c=.ll)
BPFOBJS   := $(BPFSRCS:.c=.o)
BPFBINS   := $(BPFSRCS:.c=)

all: $(BPFBINS) bpfload

clean:
	rm -f *.o *.ll $(BPFBINS) bpfload

bpfload: bpfload.o
	$(CC) $< -o $@

$(BPFBINS): $(BPFOBJS)
	$(OBJCOPY) -j bpf -O binary $< $@

$(BPFOBJS): $(BPFLLVM)
	$(LLC) $(LLFLAGS) $< -o $@

$(BPFLLVM): $(BPFSRCS)
	$(CC) $(LLVMFLAGS) $< -o $@

