/*
 * Simple bpf program loader
 * Test bpf syscall(BPF_PROG_LOAD, ...)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>

#include <sys/syscall.h>
#include <linux/bpf.h>

#define PROGRAM_NAME "bpfload"
#define MAXLOG 1024

void help(void)
{
	printf("Usage: %s type TYPE bin BIN\n", PROGRAM_NAME);
	printf("       %s type 1 bin bpf\n\n", PROGRAM_NAME);
	printf("// BPF_PROG_TYPE_UNSPEC        = 0\n");
	printf("// BPF_PROG_TYPE_SOCKET_FILTER = 1\n");
}

void *read_binary(const char *filename, size_t *nbytes)
{
	int fd;
	off_t maxoff;
	ssize_t nb = 0;
	void *mem = NULL;

	if (!filename || !nbytes)
		return NULL;

	fd = open(filename, O_RDONLY);
	if (fd == -1)
		return NULL;

	maxoff = lseek(fd, 0, SEEK_END);
	if ((maxoff == -1) || (maxoff > SSIZE_MAX))
		goto _end;
	lseek(fd, 0, SEEK_SET);

	mem = malloc(maxoff);
	if (!mem)
		goto _end;

	nb = read(fd, mem, maxoff);
	if (nb == -1) {
		free(mem);
		mem = NULL;
	}

_end:
	close(fd);
	*nbytes = (size_t)nb;
	return mem;
}

void init_bpf_attr(int type, union bpf_attr *attr, void *code, size_t nbytes, void *logbuf)
{
	// todo: set type specific initialization
	switch (type) {
		default:
		memset(attr, 0, sizeof(union bpf_attr));
	}

	attr->prog_type = type;
	attr->insn_cnt = nbytes / 8;
	attr->insns = (uint64_t) code;
	attr->license = (uint64_t) "GPL";
	attr->log_level = 1;
	attr->log_size = MAXLOG - 1;
	attr->log_buf = (uint64_t) logbuf;
	memcpy(&attr->prog_name[0], "bpfacc", 7);
}

void bpfload(int type, void *bpfcode, size_t nbytes)
{
	char logbuf[MAXLOG] = { 0 };
	union bpf_attr attr;
	int progfd;

	init_bpf_attr(type, &attr, bpfcode, nbytes, &logbuf);
	progfd = syscall(SYS_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
	printf("bpf syscall ret: %d\n", progfd);
	printf("bpf syscall log:\n%s", logbuf);
}

int main(int argc, char *argv[])
{
	int type;
	char *binary;
	size_t nbytes;
	void *bpfcode = NULL;

	/* sanity check */
	if (argc != 5) {
		help();
		exit(EXIT_FAILURE);
	}

	type = atoi(argv[2]);
	binary = argv[4];

	if (strcmp("type", argv[1]) || (strcmp("bin", argv[3]))) {
		printf("Error: expected 'type', 'bin', got: '%s', '%s'\n", argv[1], argv[3]);
		exit(EXIT_FAILURE);
	}

	if ((type < 0) || (type > 1)) {
		printf("Error: unknown type=%d\n", type);
		exit(EXIT_FAILURE);
	}

	bpfcode = read_binary(binary, &nbytes);
	if (!bpfcode) {
		perror("read_binary");
		exit(EXIT_FAILURE);
	}

	bpfload(type, bpfcode, nbytes);
	free(bpfcode);
	return EXIT_SUCCESS;
}
