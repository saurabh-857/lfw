// SPDX-License-Identifier: GPL-3.0-only

#include "lfw_bpf.h"
#include "lfw_log.h"
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>

static pthread_mutex_t g_bpf_mutex = PTHREAD_MUTEX_INITIALIZER;

void lfw_bpf_lock(void)
{
    pthread_mutex_lock(&g_bpf_mutex);
}

void lfw_bpf_unlock(void)
{
    pthread_mutex_unlock(&g_bpf_mutex);
}

static struct bpf_object *g_bpf_obj = NULL;
static int g_ifindex = 0;
static struct bpf_tc_hook g_hook_ingress = {};
static struct bpf_tc_hook g_hook_egress = {};
static struct bpf_tc_opts g_opts_ingress = {};
static struct bpf_tc_opts g_opts_egress = {};
static bool g_ingress_attached = false;
static bool g_egress_attached = false;
static bool g_qdisc_created = false;

static int g_conntrack_map_fd = -1;
static int g_rules_map_fd = -1;
static int g_config_map_fd = -1;
static int g_src_ip_trie_fd = -1;
static int g_dst_ip_trie_fd = -1;
static int g_src_ip6_trie_fd = -1;
static int g_dst_ip6_trie_fd = -1;
static int g_conntrack_map_v6_fd = -1;
static int g_events_ringbuf_fd = -1;

int lfw_bpf_get_conntrack_map_fd(void) { return g_conntrack_map_fd; }
int lfw_bpf_get_rules_map_fd(void) { return g_rules_map_fd; }
int lfw_bpf_get_config_map_fd(void) { return g_config_map_fd; }
int lfw_bpf_get_src_ip_trie_fd(void) { return g_src_ip_trie_fd; }
int lfw_bpf_get_dst_ip_trie_fd(void) { return g_dst_ip_trie_fd; }
int lfw_bpf_get_src_ip6_trie_fd(void) { return g_src_ip6_trie_fd; }
int lfw_bpf_get_dst_ip6_trie_fd(void) { return g_dst_ip6_trie_fd; }
int lfw_bpf_get_conntrack_map_v6_fd(void) { return g_conntrack_map_v6_fd; }
int lfw_bpf_get_events_ringbuf_fd(void) { return g_events_ringbuf_fd; }

static void ensure_bpf_dir(void) {
    mkdir("/sys/fs/bpf", 0755);
    mkdir("/sys/fs/bpf/lfw", 0755);
}

static void clear_pinned_maps(void) {
    unlink("/sys/fs/bpf/lfw/conntrack_map");
    unlink("/sys/fs/bpf/lfw/conntrack_map_v6");
    unlink("/sys/fs/bpf/lfw/events_ringbuf");
    rmdir("/sys/fs/bpf/lfw");
}

static void set_map_pin_paths(struct bpf_object *obj) {
    struct bpf_map *map;
    bpf_object__for_each_map(map, obj) {
        const char *name = bpf_map__name(map);
        if (strcmp(name, "conntrack_map") == 0) {
            bpf_map__set_pin_path(map, "/sys/fs/bpf/lfw/conntrack_map");
        } else if (strcmp(name, "conntrack_map_v6") == 0) {
            bpf_map__set_pin_path(map, "/sys/fs/bpf/lfw/conntrack_map_v6");
        } else if (strcmp(name, "events_ringbuf") == 0) {
            bpf_map__set_pin_path(map, "/sys/fs/bpf/lfw/events_ringbuf");
        }
    }
}

lfw_status_t lfw_bpf_init(const char *ifname, const char *bpf_obj_path)
{
    g_ifindex = if_nametoindex(ifname);
    if (g_ifindex == 0) {
        lfw_log_error("Invalid network interface: %s", ifname);
        return LFW_ERR_INVALID;
    }

    // Cold boot cleanup
    clear_pinned_maps();
    ensure_bpf_dir();

    g_bpf_obj = bpf_object__open_file(bpf_obj_path, NULL);
    if (!g_bpf_obj) {
        lfw_log_error("Failed to open BPF object file: %s", bpf_obj_path);
        return LFW_ERR_GENERIC;
    }

    set_map_pin_paths(g_bpf_obj);

    if (bpf_object__load(g_bpf_obj) != 0) {
        lfw_log_error("Failed to load BPF object file");
        bpf_object__close(g_bpf_obj);
        g_bpf_obj = NULL;
        return LFW_ERR_GENERIC;
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(g_bpf_obj, "lfw_tc_filter");
    if (!prog) {
        lfw_log_error("Failed to find BPF program 'lfw_tc_filter'");
        lfw_bpf_cleanup();
        return LFW_ERR_GENERIC;
    }

    int prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        lfw_log_error("Invalid BPF program descriptor");
        lfw_bpf_cleanup();
        return LFW_ERR_GENERIC;
    }

    g_conntrack_map_fd = bpf_object__find_map_fd_by_name(g_bpf_obj, "conntrack_map");
    g_rules_map_fd = bpf_object__find_map_fd_by_name(g_bpf_obj, "rules_details_map");
    g_config_map_fd = bpf_object__find_map_fd_by_name(g_bpf_obj, "config_map");
    g_src_ip_trie_fd = bpf_object__find_map_fd_by_name(g_bpf_obj, "src_ip_trie");
    g_dst_ip_trie_fd = bpf_object__find_map_fd_by_name(g_bpf_obj, "dst_ip_trie");
    g_src_ip6_trie_fd = bpf_object__find_map_fd_by_name(g_bpf_obj, "src_ip6_trie");
    g_dst_ip6_trie_fd = bpf_object__find_map_fd_by_name(g_bpf_obj, "dst_ip6_trie");
    g_conntrack_map_v6_fd = bpf_object__find_map_fd_by_name(g_bpf_obj, "conntrack_map_v6");
    g_events_ringbuf_fd = bpf_object__find_map_fd_by_name(g_bpf_obj, "events_ringbuf");

    if (g_conntrack_map_fd < 0 || g_rules_map_fd < 0 || g_config_map_fd < 0 ||
        g_src_ip_trie_fd < 0 || g_dst_ip_trie_fd < 0 ||
        g_src_ip6_trie_fd < 0 || g_dst_ip6_trie_fd < 0 || g_conntrack_map_v6_fd < 0 ||
        g_events_ringbuf_fd < 0) {
        lfw_log_error("Failed to find required BPF maps");
        lfw_bpf_cleanup();
        return LFW_ERR_GENERIC;
    }

    // Set up hook for ingress
    g_hook_ingress.sz = sizeof(struct bpf_tc_hook);
    g_hook_ingress.ifindex = g_ifindex;
    g_hook_ingress.attach_point = BPF_TC_INGRESS;

    // Destroy any stale qdisc/filters from previous crashed runs to ensure a clean slate
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "tc qdisc del dev %s clsact >/dev/null 2>&1", ifname);
    system(cmd);

    // Create clsact qdisc (this will create it for both ingress/egress hooks)
    int err = bpf_tc_hook_create(&g_hook_ingress);
    if (err && err != -EEXIST) {
        lfw_log_error("Failed to create clsact qdisc: %s", strerror(-err));
        lfw_bpf_cleanup();
        return LFW_ERR_GENERIC;
    }
    g_qdisc_created = true;

    // Attach to ingress
    g_opts_ingress.sz = sizeof(struct bpf_tc_opts);
    g_opts_ingress.prog_fd = prog_fd;
    g_opts_ingress.flags = BPF_TC_F_REPLACE;

    err = bpf_tc_attach(&g_hook_ingress, &g_opts_ingress);
    if (err) {
        lfw_log_error("Failed to attach BPF program to ingress: %s", strerror(-err));
        lfw_bpf_cleanup();
        return LFW_ERR_GENERIC;
    }
    g_ingress_attached = true;

    // Set up hook and attach for egress
    g_hook_egress.sz = sizeof(struct bpf_tc_hook);
    g_hook_egress.ifindex = g_ifindex;
    g_hook_egress.attach_point = BPF_TC_EGRESS;

    g_opts_egress.sz = sizeof(struct bpf_tc_opts);
    g_opts_egress.prog_fd = prog_fd;
    g_opts_egress.flags = BPF_TC_F_REPLACE;

    err = bpf_tc_attach(&g_hook_egress, &g_opts_egress);
    if (err) {
        lfw_log_error("Failed to attach BPF program to egress: %s", strerror(-err));
        lfw_bpf_cleanup();
        return LFW_ERR_GENERIC;
    }
    g_egress_attached = true;

    lfw_log_info("Successfully attached eBPF/TC program to %s (ingress & egress)", ifname);
    return LFW_OK;
}

void lfw_bpf_cleanup(void)
{
    if (g_ingress_attached) {
        g_opts_ingress.flags = 0;
        g_opts_ingress.prog_fd = 0;
        g_opts_ingress.prog_id = 0;
        int err = bpf_tc_detach(&g_hook_ingress, &g_opts_ingress);
        if (err) {
            lfw_log_error("Failed to detach ingress BPF program: %s", strerror(-err));
        }
        g_ingress_attached = false;
    }
    if (g_egress_attached) {
        g_opts_egress.flags = 0;
        g_opts_egress.prog_fd = 0;
        g_opts_egress.prog_id = 0;
        int err = bpf_tc_detach(&g_hook_egress, &g_opts_egress);
        if (err) {
            lfw_log_error("Failed to detach egress BPF program: %s", strerror(-err));
        }
        g_egress_attached = false;
    }
    if (g_qdisc_created) {
        int err = bpf_tc_hook_destroy(&g_hook_ingress);
        if (err) {
            lfw_log_error("Failed to destroy clsact qdisc: %s", strerror(-err));
        }
        g_qdisc_created = false;
    }
    if (g_bpf_obj) {
        bpf_object__close(g_bpf_obj);
        g_bpf_obj = NULL;
    }
    g_conntrack_map_fd = -1;
    g_rules_map_fd = -1;
    g_config_map_fd = -1;
    g_src_ip_trie_fd = -1;
    g_dst_ip_trie_fd = -1;
    g_src_ip6_trie_fd = -1;
    g_dst_ip6_trie_fd = -1;
    g_conntrack_map_v6_fd = -1;
    g_events_ringbuf_fd = -1;

    clear_pinned_maps();
}

lfw_status_t lfw_bpf_reload(const char *ifname, const char *bpf_obj_path,
                            const lfw_rule_t *new_rules, lfw_u32 new_rule_count,
                            lfw_action_t new_default_action, lfw_loglevel_t log_level)
{
    int new_ifindex = if_nametoindex(ifname);
    if (new_ifindex == 0) {
        lfw_log_error("Reload: Invalid network interface: %s", ifname);
        return LFW_ERR_INVALID;
    }

    ensure_bpf_dir();

    struct bpf_object *new_obj = bpf_object__open_file(bpf_obj_path, NULL);
    if (!new_obj) {
        lfw_log_error("Reload: Failed to open BPF object file: %s", bpf_obj_path);
        return LFW_ERR_GENERIC;
    }

    set_map_pin_paths(new_obj);

    if (bpf_object__load(new_obj) != 0) {
        lfw_log_error("Reload: Failed to load BPF object file");
        bpf_object__close(new_obj);
        return LFW_ERR_GENERIC;
    }

    struct bpf_program *new_prog = bpf_object__find_program_by_name(new_obj, "lfw_tc_filter");
    if (!new_prog) {
        lfw_log_error("Reload: Failed to find BPF program 'lfw_tc_filter'");
        bpf_object__close(new_obj);
        return LFW_ERR_GENERIC;
    }

    int new_prog_fd = bpf_program__fd(new_prog);
    if (new_prog_fd < 0) {
        lfw_log_error("Reload: Invalid BPF program descriptor");
        bpf_object__close(new_obj);
        return LFW_ERR_GENERIC;
    }

    int rules_fd = bpf_object__find_map_fd_by_name(new_obj, "rules_details_map");
    int config_fd = bpf_object__find_map_fd_by_name(new_obj, "config_map");
    int src_trie_fd = bpf_object__find_map_fd_by_name(new_obj, "src_ip_trie");
    int dst_trie_fd = bpf_object__find_map_fd_by_name(new_obj, "dst_ip_trie");
    int src_trie6_fd = bpf_object__find_map_fd_by_name(new_obj, "src_ip6_trie");
    int dst_trie6_fd = bpf_object__find_map_fd_by_name(new_obj, "dst_ip6_trie");

    if (rules_fd < 0 || config_fd < 0 || src_trie_fd < 0 || dst_trie_fd < 0 ||
        src_trie6_fd < 0 || dst_trie6_fd < 0) {
        lfw_log_error("Reload: Failed to find required maps in new object");
        bpf_object__close(new_obj);
        return LFW_ERR_GENERIC;
    }

    lfw_status_t st = lfw_bpf_sync_rules_to_fd(new_rules, new_rule_count, new_default_action, log_level,
                                               rules_fd, config_fd, src_trie_fd, dst_trie_fd,
                                               src_trie6_fd, dst_trie6_fd);
    if (st != LFW_OK) {
        lfw_log_error("Reload: Failed to sync rules to new maps");
        bpf_object__close(new_obj);
        return LFW_ERR_GENERIC;
    }

    struct bpf_tc_opts new_opts_ingress = {};
    new_opts_ingress.sz = sizeof(struct bpf_tc_opts);
    new_opts_ingress.prog_fd = new_prog_fd;
    new_opts_ingress.flags = BPF_TC_F_REPLACE;

    int err = bpf_tc_attach(&g_hook_ingress, &new_opts_ingress);
    if (err) {
        lfw_log_error("Reload: Failed to replace ingress filter: %s", strerror(-err));
        bpf_object__close(new_obj);
        return LFW_ERR_GENERIC;
    }

    struct bpf_tc_opts new_opts_egress = {};
    new_opts_egress.sz = sizeof(struct bpf_tc_opts);
    new_opts_egress.prog_fd = new_prog_fd;
    new_opts_egress.flags = BPF_TC_F_REPLACE;

    err = bpf_tc_attach(&g_hook_egress, &new_opts_egress);
    if (err) {
        lfw_log_error("Reload: Failed to replace egress filter: %s", strerror(-err));
        // Rollback ingress filter to previous configuration
        int rollback_err = bpf_tc_attach(&g_hook_ingress, &g_opts_ingress);
        if (rollback_err) {
            lfw_log_error("Reload: Fatal - failed to rollback ingress filter: %s", strerror(-rollback_err));
        }
        bpf_object__close(new_obj);
        return LFW_ERR_GENERIC;
    }

    if (g_bpf_obj) {
        bpf_object__close(g_bpf_obj);
    }

    g_bpf_obj = new_obj;
    g_ifindex = new_ifindex;
    g_opts_ingress = new_opts_ingress;
    g_opts_egress = new_opts_egress;

    g_conntrack_map_fd = bpf_object__find_map_fd_by_name(new_obj, "conntrack_map");
    g_rules_map_fd = rules_fd;
    g_config_map_fd = config_fd;
    g_src_ip_trie_fd = src_trie_fd;
    g_dst_ip_trie_fd = dst_trie_fd;
    g_src_ip6_trie_fd = src_trie6_fd;
    g_dst_ip6_trie_fd = dst_trie6_fd;
    g_conntrack_map_v6_fd = bpf_object__find_map_fd_by_name(new_obj, "conntrack_map_v6");
    g_events_ringbuf_fd = bpf_object__find_map_fd_by_name(new_obj, "events_ringbuf");

    lfw_log_info("Reload: Successfully atomically reloaded BPF program on %s", ifname);
    return LFW_OK;
}
