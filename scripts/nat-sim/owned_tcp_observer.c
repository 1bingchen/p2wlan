/* Read-only, direct-owner Darwin diagnostics. No network or payload I/O. */
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <libproc.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/proc_info.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define MAX_FDS 128
#define MAX_COMMANDS 7
struct row {
    int fd, state, local_port, foreign_port, queue, incomplete, limit, error;
    uint64_t generation;
    char local_address[INET_ADDRSTRLEN], foreign_address[INET_ADDRSTRLEN];
};
static int request_id;
static pid_t owner;
static struct proc_bsdinfo owner_identity;

static int fail(const char *event, const char *reason, int error) {
    printf("{\"schema\":3,\"event\":\"%s\",\"request_id\":%d,\"valid\":false,"
           "\"reason\":\"%s\",\"errno\":%d}\n", event, request_id, reason, error);
    return 1;
}

static int birth(pid_t pid, struct proc_bsdinfo *out) {
    return proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, out, sizeof(*out)) == (int)sizeof(*out);
}

static int same(const struct proc_bsdinfo *a, const struct proc_bsdinfo *b) {
    return a->pbi_pid == b->pbi_pid && a->pbi_uid == b->pbi_uid &&
           a->pbi_start_tvsec == b->pbi_start_tvsec && a->pbi_start_tvusec == b->pbi_start_tvusec;
}

static int owner_current(void) {
    struct proc_bsdinfo now;
    return getppid() == owner && birth(owner, &now) && same(&owner_identity, &now);
}

static int number(const char *text, uint64_t maximum, int zero, uint64_t *out) {
    if (!*text || strspn(text, "0123456789") != strlen(text)) return 0;
    char *end;
    errno = 0;
    unsigned long long n = strtoull(text, &end, 10);
    if (errno || *end || (!zero && !n) || n > maximum) return 0;
    *out = (uint64_t)n;
    return 1;
}

static int observe(pid_t pid, int port, int identity, uint64_t seconds, uint64_t micros) {
    const char *event = identity ? "identity" : "sample";
    struct proc_bsdinfo before, after;
    uint64_t started = clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
    if (!owner_current()) return fail(event, "owner_replaced_or_unavailable", 0);
    if (!birth(pid, &before)) return fail(event, "birth_unavailable", errno);
    if (before.pbi_pid != (uint32_t)pid || before.pbi_uid != getuid())
        return fail(event, "foreign_identity", 0);
    if (pid != owner && before.pbi_ppid != (uint32_t)owner)
        return fail(event, "not_owned_parent_or_child", 0);
    if (!identity && (before.pbi_start_tvsec != seconds || before.pbi_start_tvusec != micros))
        return fail(event, "expected_birth_mismatch", 0);
    struct row rows[MAX_FDS];
    int count = 0, fd_count = 0, races = 0;
    if (!identity) {
        int needed = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
        if (needed <= 0) return fail(event, "fd_inventory_unavailable_or_empty", errno);
        if (needed >= (int)(MAX_FDS * sizeof(struct proc_fdinfo)))
            return fail(event, "fd_capacity", 0);
        struct proc_fdinfo fds[MAX_FDS];
        int bytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds, sizeof(fds));
        if (bytes <= 0) return fail(event, "fd_inventory_unavailable_or_empty", errno);
        if (bytes >= (int)sizeof(fds) || bytes % sizeof(struct proc_fdinfo))
            return fail(event, "fd_inventory_size", 0);
        fd_count = bytes / (int)sizeof(struct proc_fdinfo);
        for (int i = 0; i < fd_count; i++) {
            if (fds[i].proc_fdtype != PROX_FDTYPE_SOCKET) continue;
            struct socket_fdinfo info;
            if (proc_pidfdinfo(pid, fds[i].proc_fd, PROC_PIDFDSOCKETINFO, &info, sizeof(info)) != (int)sizeof(info)) {
                races++;
                continue;
            }
            const struct socket_info *socket = &info.psi;
            if (socket->soi_family != AF_INET || socket->soi_type != SOCK_STREAM ||
                socket->soi_protocol != IPPROTO_TCP || socket->soi_kind != SOCKINFO_TCP) continue;
            const struct tcp_sockinfo *tcp = &socket->soi_proto.pri_tcp;
            int local = ntohs((uint16_t)tcp->tcpsi_ini.insi_lport);
            int foreign = ntohs((uint16_t)tcp->tcpsi_ini.insi_fport);
            if (local != port && foreign != port) continue;
            rows[count] = (struct row){fds[i].proc_fd, tcp->tcpsi_state, local, foreign,
                socket->soi_qlen, socket->soi_incqlen, socket->soi_qlimit, socket->soi_error,
                tcp->tcpsi_ini.insi_gencnt, {0}, {0}};
            if (!inet_ntop(AF_INET, &tcp->tcpsi_ini.insi_laddr.ina_46.i46a_addr4,
                           rows[count].local_address, INET_ADDRSTRLEN) ||
                !inet_ntop(AF_INET, &tcp->tcpsi_ini.insi_faddr.ina_46.i46a_addr4,
                           rows[count].foreign_address, INET_ADDRSTRLEN)) {
                races++;
                continue;
            }
            count++;
        }
    }
    if (!birth(pid, &after)) return fail(event, "birth_unavailable_after_read", errno);
    if (!same(&before, &after)) return fail(event, "process_replaced", 0);
    if (pid != owner && after.pbi_ppid != (uint32_t)owner)
        return fail(event, "process_ownership_changed", 0);
    /* Check the actual owner again after every target/FD read, including identity. */
    if (!owner_current()) return fail(event, "owner_replaced_or_unavailable_after_read", 0);
    uint64_t ended = clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
    printf("{\"schema\":3,\"event\":\"%s\",\"request_id\":%d,\"valid\":true,"
           "\"pid\":%d,\"ppid\":%u,\"uid\":%u,\"birth_seconds\":%" PRIu64 ",\"birth_microseconds\":%" PRIu64 ","
           "\"started_uptime_raw_ns\":%" PRIu64 ",\"ended_uptime_raw_ns\":%" PRIu64 ",",
           event, request_id, pid, before.pbi_ppid, before.pbi_uid,
           before.pbi_start_tvsec, before.pbi_start_tvusec, started, ended);
    if (identity) {
        puts("\"scope\":\"owned_process_identity_only\",\"socket_observation\":false}");
        return 0;
    }
    printf("\"expected_birth_supplied\":true,\"ipv4_tcp_only\":true,\"complete\":%s,"
           "\"fd_count\":%d,\"socket_races\":%d,\"rows\":[", races ? "false" : "true", fd_count, races);
    for (int i = 0; i < count; i++) {
        const struct row *r = &rows[i];
        printf("%s{\"fd\":%d,\"socket_generation\":%" PRIu64 ",\"tcp_state\":%d,"
               "\"local_port\":%d,\"foreign_port\":%d,\"completed_queue\":%d,\"incomplete_queue\":%d,"
               "\"queue_limit\":%d,\"socket_error\":%d,\"local_address\":\"%s\",\"foreign_address\":\"%s\"}",
               i ? "," : "", r->fd, r->generation, r->state, r->local_port, r->foreign_port,
               r->queue, r->incomplete, r->limit, r->error, r->local_address, r->foreign_address);
    }
    puts("]}");
    return 0;
}

int main(int argc, char **argv) {
    (void)argv;
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc != 1) return fail("ready", "arguments", 0);
    owner = getppid();
    alarm(10);
    if (!birth(owner, &owner_identity) || owner_identity.pbi_uid != getuid())
        return fail("ready", "owner_birth_unavailable", errno);
    printf("{\"schema\":3,\"event\":\"ready\",\"observer_pid\":%d,\"owner_pid\":%d,"
           "\"owner_birth_seconds\":%" PRIu64 ",\"owner_birth_microseconds\":%" PRIu64 ","
           "\"max_commands\":8,\"max_nonquit\":7,\"max_fds\":128}\n",
           getpid(), owner, owner_identity.pbi_start_tvsec, owner_identity.pbi_start_tvusec);
    char line[128];
    for (int n = 1; n <= MAX_COMMANDS + 1; n++) {
        if (!fgets(line, sizeof(line), stdin)) return 0;
        if (!strcmp(line, "quit\n")) return 0;
        if (n > MAX_COMMANDS) return fail("sample", "command_limit", 0);
        if (!strchr(line, '\n')) return fail("sample", "command_capacity", 0);
        char *parts[7], *save = NULL;
        int count = 0;
        char *part = strtok_r(line, " \t\r\n", &save);
        while (part && count < 7) { parts[count++] = part; part = strtok_r(NULL, " \t\r\n", &save); }
        int identity = count > 0 && !strcmp(parts[0], "identity");
        if (part || count != (identity ? 4 : 6) || (!identity && strcmp(parts[0], "sample")))
            return fail("sample", "command_arguments", 0);
        uint64_t id, pid, port, seconds = 0, micros = 0;
        if (!number(parts[1], MAX_COMMANDS, 0, &id) || id != (uint64_t)n ||
            !number(parts[2], INT_MAX, 0, &pid) || !number(parts[3], 65535, 0, &port) ||
            (!identity && (!number(parts[4], UINT64_MAX, 0, &seconds) || !number(parts[5], 999999, 1, &micros))))
            return fail("sample", "command_arguments", 0);
        request_id = (int)id;
        (void)observe((pid_t)pid, (int)port, identity, seconds, micros);
    }
    return 0;
}
