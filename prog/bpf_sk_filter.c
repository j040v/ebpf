/*
 * bpf socket filter example
 */

#include <linux/bpf.h>
#include "compiler.h"

__use_bpf_helper(get_socket_cookie, struct __sk_buff *, BPF_FUNC_get_socket_cookie);

#ifdef USE_NETNS_COOKIE
__use_bpf_helper(get_netns_cookie, struct __sk_buff *, BPF_FUNC_get_netns_cookie);
#endif

__bpf_section
int socket_filter(struct __sk_buff *ctx)
{
	u64 sock_cookie, netns_cookie __maybe_unused = 0;
	sock_cookie = get_socket_cookie(ctx);
#ifdef USE_NETNS_COOKIE
	netns_cookie = get_netns_cookie(ctx);
#endif
	printk("socket_filter: sock_cookie=0x%llx, netns_cookie=0x%llx\n", sock_cookie, netns_cookie);
	return 0;
}
