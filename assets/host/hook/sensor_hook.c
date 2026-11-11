/*
 * libsensor.so — LD_PRELOAD sensor hook for the SOC lab host containers (spec section 4).
 *
 * Loaded through /etc/ld.so.preload. Interposes the public libc entry points programs use to start
 * programs, open files and make connections, and reports each call as one JSON object on the Unix
 * datagram socket /run/sensor/hook.sock. Reporting never changes the call's behaviour: every send is
 * non-blocking and every error is ignored, so programs work normally when no sensor is listening.
 *
 * Interposition works per exported symbol, and libc's internal calls bypass it, so every public entry
 * point is hooked separately. Statically linked binaries and raw syscalls are not seen (known limit).
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#define SOCK_PATH "/run/sensor/hook.sock"
#define FIELD_BUDGET 4096 /* bytes of argv/path text per event, before escaping */
#define BUF_SIZE 8000     /* whole JSON event stays under 8 KB */
#define RESERVE 128       /* kept free for closing quotes and brackets and the fixed trailing fields */
#define MAX_ARGS 1024

static __thread int in_hook; /* re-entrancy guard: our own libc calls are never reported */

/* ---------- JSON event buffer ---------- */

/*
 * Every event must be valid JSON, however much escaping its text needs. Variable text (string contents,
 * further argv entries) is only added while it fits in BUF_SIZE - RESERVE; what does not fit is dropped
 * and the event marked truncated. Structure (quotes, brackets, separators, fixed fields) always goes in,
 * using the RESERVE, so a string or array is never left open.
 */
struct jbuf {
    char data[BUF_SIZE];
    size_t len;
    size_t budget; /* remaining FIELD_BUDGET */
    int truncated;
    int broken;    /* structure did not fit: never sent (cannot happen while RESERVE covers the closers) */
};

static int jb_fits(const struct jbuf *b, size_t n) { return b->len + n <= BUF_SIZE - RESERVE; }

static void jb_raw(struct jbuf *b, const char *s, size_t n) {
    if (b->len + n > BUF_SIZE) { b->broken = 1; return; }
    memcpy(b->data + b->len, s, n);
    b->len += n;
}

static void jb_lit(struct jbuf *b, const char *s) { jb_raw(b, s, strlen(s)); }

static void jb_num(struct jbuf *b, const char *key, long long v) {
    char tmp[96];
    int n = snprintf(tmp, sizeof tmp, ",\"%s\":%lld", key, v);
    jb_raw(b, tmp, (size_t)n);
}

/*
 * Length of a well-formed UTF-8 sequence starting at s (n bytes available), or 0 if it is not one.
 * Strict (RFC 3629): no overlong forms, no surrogates (U+D800..U+DFFF), nothing above U+10FFFF.
 */
static size_t utf8_len(const unsigned char *s, size_t n) {
    unsigned char c = s[0];
    if (c < 0x80) return 1;
    size_t len;
    unsigned char lo = 0x80, hi = 0xBF; /* allowed range of the second byte */
    if (c >= 0xC2 && c <= 0xDF) len = 2;
    else if (c >= 0xE0 && c <= 0xEF) { len = 3; if (c == 0xE0) lo = 0xA0; if (c == 0xED) hi = 0x9F; }
    else if (c >= 0xF0 && c <= 0xF4) { len = 4; if (c == 0xF0) lo = 0x90; if (c == 0xF4) hi = 0x8F; }
    else return 0;
    if (len > n || s[1] < lo || s[1] > hi) return 0;
    for (size_t i = 2; i < len; i++)
        if ((s[i] & 0xC0) != 0x80) return 0;
    return len;
}

/*
 * Append a JSON string value; it is always closed. Each byte that is not part of well-formed UTF-8
 * becomes the 4 characters \xNN. Each character goes in whole or not at all.
 */
static void jb_str(struct jbuf *b, const char *s) {
    jb_raw(b, "\"", 1);
    const unsigned char *p = (const unsigned char *)(s ? s : "");
    size_t n = strlen((const char *)p);
    for (size_t i = 0; i < n;) {
        if (b->budget == 0) { b->truncated = 1; break; }
        unsigned char c = p[i];
        char tmp[8];
        const char *piece = tmp;
        size_t len, used = 1; /* output bytes, input bytes */
        size_t ulen = utf8_len(p + i, n - i);
        if (ulen == 0) {
            len = (size_t)snprintf(tmp, sizeof tmp, "\\\\x%02x", c);
        } else if (c == '"' || c == '\\') {
            tmp[0] = '\\'; tmp[1] = (char)c; len = 2;
        } else if (c < 0x20) {
            len = (size_t)snprintf(tmp, sizeof tmp, "\\u%04x", c);
        } else {
            piece = (const char *)p + i; len = used = ulen;
        }
        if (!jb_fits(b, len)) { b->truncated = 1; break; }
        jb_raw(b, piece, len);
        i += used;
        b->budget = b->budget > used ? b->budget - used : 0;
    }
    jb_raw(b, "\"", 1);
}

static void jb_begin(struct jbuf *b, const char *kind, pid_t pid, pid_t ppid) {
    struct timeval tv;
    char comm[17] = {0};
    char tmp[64];
    b->len = 0; b->budget = FIELD_BUDGET; b->truncated = 0; b->broken = 0;
    gettimeofday(&tv, NULL);
    prctl(PR_GET_NAME, comm, 0, 0, 0);
    int n = snprintf(tmp, sizeof tmp, "{\"t\":%ld.%06ld", (long)tv.tv_sec, (long)tv.tv_usec);
    jb_raw(b, tmp, (size_t)n);
    jb_num(b, "pid", pid);
    jb_num(b, "ppid", ppid);
    jb_num(b, "uid", (long long)getuid());
    jb_lit(b, ",\"comm\":"); jb_str(b, comm);
    jb_lit(b, ",\"kind\":"); jb_str(b, kind);
}

static void jb_send(struct jbuf *b) {
    jb_lit(b, b->truncated ? ",\"truncated\":true}" : ",\"truncated\":false}");
    if (b->broken) return; /* never send malformed JSON */
    int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return;
    struct sockaddr_un addr = {.sun_family = AF_UNIX};
    strncpy(addr.sun_path, SOCK_PATH, sizeof addr.sun_path - 1);
    (void)sendto(fd, b->data, b->len, MSG_DONTWAIT | MSG_NOSIGNAL, (struct sockaddr *)&addr, sizeof addr);
    close(fd);
}

/* ---------- reporters ---------- */

static void report_exec(pid_t pid, pid_t ppid, char *const argv[], const char *fallback) {
    int saved = errno;
    struct jbuf b;
    jb_begin(&b, "exec", pid, ppid);
    jb_lit(&b, ",\"argv\":[");
    if (argv && argv[0]) {
        for (int i = 0; argv[i] && i < MAX_ARGS; i++) {
            /* an argument goes in only while there is room for at least `,""` of it */
            if (i && (b.truncated || !jb_fits(&b, 3))) { b.truncated = 1; break; }
            if (i) jb_lit(&b, ",");
            jb_str(&b, argv[i]);
            if (b.budget == 0 && argv[i + 1]) { b.truncated = 1; break; }
        }
    } else {
        jb_str(&b, fallback);
    }
    jb_lit(&b, "]");
    jb_send(&b);
    errno = saved;
}

static int watched(const char *path, int write) {
    if (strcmp(path, "/etc/shadow") == 0) return 1;
    if (strcmp(path, "/etc/ld.so.preload") == 0) return 1;
    if (!write) return 0;
    return strcmp(path, "/etc/passwd") == 0 || strncmp(path, "/etc/cron", 9) == 0 ||
           strncmp(path, "/var/spool/cron/", 16) == 0;
}

/* Resolve a path relative to dirfd (or the cwd) into abs; returns abs or the original path. */
static const char *absolute(int dirfd, const char *path, char *abs, size_t size) {
    if (!path || path[0] == '/') return path;
    char base[PATH_MAX];
    if (dirfd == AT_FDCWD) {
        if (!getcwd(base, sizeof base)) return path;
    } else {
        char link[64];
        snprintf(link, sizeof link, "/proc/self/fd/%d", dirfd);
        ssize_t n = readlink(link, base, sizeof base - 1);
        if (n < 0) return path;
        base[n] = 0;
    }
    int n = snprintf(abs, size, "%s/%s", base, path);
    return n > 0 && (size_t)n < size ? abs : path;
}

#define ACC_READ 1
#define ACC_WRITE 2

static void send_open(const char *p, int write) {
    struct jbuf b;
    jb_begin(&b, "open", getpid(), getppid());
    jb_lit(&b, ",\"path\":"); jb_str(&b, p);
    jb_lit(&b, write ? ",\"mode\":\"write\"" : ",\"mode\":\"read\""); /* fixed: not cut by a long path */
    jb_send(&b);
}

/* Report an open with the given ACC_* access. A read-write open is reported as both a read and a write. */
static void report_open(int dirfd, const char *path, int access) {
    if (!path) return;
    int saved = errno;
    char abs[PATH_MAX];
    const char *p = absolute(dirfd, path, abs, sizeof abs);
    if ((access & ACC_READ) && watched(p, 0)) send_open(p, 0);
    if ((access & ACC_WRITE) && watched(p, 1)) send_open(p, 1);
    errno = saved;
}

static int flags_access(int flags) {
    int acc = flags & O_ACCMODE, a = 0;
    if (acc == O_RDONLY || acc == O_RDWR) a |= ACC_READ;
    if (acc != O_RDONLY || (flags & (O_CREAT | O_TRUNC))) a |= ACC_WRITE;
    return a;
}

/* fopen modes: "r" reads; "w", "a", "x" write; a '+' anywhere adds the other direction. */
static int fmode_access(const char *mode) {
    if (!mode || !mode[0]) return 0;
    int a = mode[0] == 'r' ? ACC_READ : ACC_WRITE;
    return strchr(mode, '+') ? ACC_READ | ACC_WRITE : a;
}

static void report_connect(const struct sockaddr *sa) {
    if (!sa || (sa->sa_family != AF_INET && sa->sa_family != AF_INET6)) return;
    int saved = errno;
    char ip[INET6_ADDRSTRLEN] = {0};
    int port;
    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in *in = (const struct sockaddr_in *)sa;
        inet_ntop(AF_INET, &in->sin_addr, ip, sizeof ip);
        port = ntohs(in->sin_port);
    } else {
        const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)sa;
        inet_ntop(AF_INET6, &in6->sin6_addr, ip, sizeof ip);
        port = ntohs(in6->sin6_port);
    }
    struct jbuf b;
    jb_begin(&b, "connect", getpid(), getppid());
    jb_lit(&b, ",\"ip\":"); jb_str(&b, ip);
    jb_num(&b, "port", port);
    jb_send(&b);
    errno = saved;
}

/* ---------- interposition helpers ---------- */

/* Resolve the next definition of `name`. The pointer type comes from our own (identical) declaration. */
#define REAL(name, type)                                   \
    static __typeof__(name) *real_##name;                  \
    if (!real_##name) real_##name = (__typeof__(name) *)dlsym(RTLD_NEXT, #name)
#define GUARDED(stmt) do { if (!in_hook) { in_hook = 1; stmt; in_hook = 0; } } while (0)

static int collect_va(const char *arg0, va_list ap, char **argv, char ***envp_out) {
    int n = 0;
    argv[n++] = (char *)arg0;
    char *a;
    while ((a = va_arg(ap, char *)) != NULL && n < MAX_ARGS - 1) argv[n++] = a;
    while (a != NULL) a = va_arg(ap, char *); /* drain anything past MAX_ARGS */
    argv[n] = NULL;
    if (envp_out) *envp_out = va_arg(ap, char **);
    return n;
}

/* ---------- exec family ---------- */

int execve(const char *path, char *const argv[], char *const envp[]) {
    REAL(execve, int (*)(const char *, char *const[], char *const[]));
    GUARDED(report_exec(getpid(), getppid(), argv, path));
    return real_execve(path, argv, envp);
}

int execv(const char *path, char *const argv[]) {
    REAL(execv, int (*)(const char *, char *const[]));
    GUARDED(report_exec(getpid(), getppid(), argv, path));
    return real_execv(path, argv);
}

int execvp(const char *file, char *const argv[]) {
    REAL(execvp, int (*)(const char *, char *const[]));
    GUARDED(report_exec(getpid(), getppid(), argv, file));
    return real_execvp(file, argv);
}

int execvpe(const char *file, char *const argv[], char *const envp[]) {
    REAL(execvpe, int (*)(const char *, char *const[], char *const[]));
    GUARDED(report_exec(getpid(), getppid(), argv, file));
    return real_execvpe(file, argv, envp);
}

int execveat(int dirfd, const char *path, char *const argv[], char *const envp[], int flags) {
    REAL(execveat, int (*)(int, const char *, char *const[], char *const[], int));
    GUARDED(report_exec(getpid(), getppid(), argv, path));
    return real_execveat(dirfd, path, argv, envp, flags);
}

int fexecve(int fd, char *const argv[], char *const envp[]) {
    REAL(fexecve, int (*)(int, char *const[], char *const[]));
    GUARDED(report_exec(getpid(), getppid(), argv, "fexecve"));
    return real_fexecve(fd, argv, envp);
}

int execl(const char *path, const char *arg, ...) {
    char *argv[MAX_ARGS];
    va_list ap;
    va_start(ap, arg);
    collect_va(arg, ap, argv, NULL);
    va_end(ap);
    return execv(path, argv);
}

int execlp(const char *file, const char *arg, ...) {
    char *argv[MAX_ARGS];
    va_list ap;
    va_start(ap, arg);
    collect_va(arg, ap, argv, NULL);
    va_end(ap);
    return execvp(file, argv);
}

int execle(const char *path, const char *arg, ...) {
    char *argv[MAX_ARGS];
    char **envp;
    va_list ap;
    va_start(ap, arg);
    collect_va(arg, ap, argv, &envp);
    va_end(ap);
    return execve(path, argv, envp);
}

typedef int (*spawn_fn)(pid_t *, const char *, const posix_spawn_file_actions_t *, const posix_spawnattr_t *,
                        char *const[], char *const[]);

static int spawn_common(spawn_fn real, pid_t *pid, const char *path, const posix_spawn_file_actions_t *fa,
                        const posix_spawnattr_t *attr, char *const argv[], char *const envp[]) {
    pid_t child = 0;
    int rc = real(&child, path, fa, attr, argv, envp);
    if (pid) *pid = child;
    if (rc == 0) GUARDED(report_exec(child, getpid(), argv, path));
    return rc;
}

int posix_spawn(pid_t *pid, const char *path, const posix_spawn_file_actions_t *fa, const posix_spawnattr_t *attr,
                char *const argv[], char *const envp[]) {
    REAL(posix_spawn, spawn_fn);
    return spawn_common(real_posix_spawn, pid, path, fa, attr, argv, envp);
}

int posix_spawnp(pid_t *pid, const char *file, const posix_spawn_file_actions_t *fa,
                 const posix_spawnattr_t *attr, char *const argv[], char *const envp[]) {
    REAL(posix_spawnp, spawn_fn);
    return spawn_common(real_posix_spawnp, pid, file, fa, attr, argv, envp);
}

/* ---------- open family ---------- */

static mode_t va_mode(int flags, va_list ap) {
    return (flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE ? (mode_t)va_arg(ap, int) : 0;
}

#define OPEN_HOOK(name)                                                                \
    int name(const char *path, int flags, ...) {                                       \
        REAL(name, int (*)(const char *, int, ...));                                   \
        va_list ap; va_start(ap, flags); mode_t mode = va_mode(flags, ap); va_end(ap); \
        GUARDED(report_open(AT_FDCWD, path, flags_access(flags)));                       \
        return real_##name(path, flags, mode);                                         \
    }
OPEN_HOOK(open)
OPEN_HOOK(open64)

#define OPENAT_HOOK(name)                                                              \
    int name(int dirfd, const char *path, int flags, ...) {                            \
        REAL(name, int (*)(int, const char *, int, ...));                              \
        va_list ap; va_start(ap, flags); mode_t mode = va_mode(flags, ap); va_end(ap); \
        GUARDED(report_open(dirfd, path, flags_access(flags)));                          \
        return real_##name(dirfd, path, flags, mode);                                  \
    }
OPENAT_HOOK(openat)
OPENAT_HOOK(openat64)

#define OPEN2_HOOK(name)                                                \
    int name(const char *path, int flags) {                             \
        REAL(name, int (*)(const char *, int));                         \
        GUARDED(report_open(AT_FDCWD, path, flags_access(flags)));        \
        return real_##name(path, flags);                                \
    }
OPEN2_HOOK(__open_2)
OPEN2_HOOK(__open64_2)

#define OPENAT2_HOOK(name)                                              \
    int name(int dirfd, const char *path, int flags) {                  \
        REAL(name, int (*)(int, const char *, int));                    \
        GUARDED(report_open(dirfd, path, flags_access(flags)));           \
        return real_##name(dirfd, path, flags);                         \
    }
OPENAT2_HOOK(__openat_2)
OPENAT2_HOOK(__openat64_2)

#define CREAT_HOOK(name)                                                \
    int name(const char *path, mode_t mode) {                           \
        REAL(name, int (*)(const char *, mode_t));                      \
        GUARDED(report_open(AT_FDCWD, path, ACC_WRITE));                         \
        return real_##name(path, mode);                                 \
    }
CREAT_HOOK(creat)
CREAT_HOOK(creat64)

#define FOPEN_HOOK(name)                                                \
    FILE *name(const char *path, const char *mode) {                    \
        REAL(name, FILE *(*)(const char *, const char *));              \
        GUARDED(report_open(AT_FDCWD, path, fmode_access(mode)));         \
        return real_##name(path, mode);                                 \
    }
FOPEN_HOOK(fopen)
FOPEN_HOOK(fopen64)

#define FREOPEN_HOOK(name)                                                      \
    FILE *name(const char *path, const char *mode, FILE *stream) {              \
        REAL(name, FILE *(*)(const char *, const char *, FILE *));              \
        GUARDED(report_open(AT_FDCWD, path, fmode_access(mode)));                 \
        return real_##name(path, mode, stream);                                 \
    }
FREOPEN_HOOK(freopen)
FREOPEN_HOOK(freopen64)

/* Temp files and renames: tools such as crontab and useradd write a temp file, then rename it. */
#define MKSTEMP_HOOK(name, params, args)                                \
    int name params {                                                   \
        REAL(name, int (*) params);                                     \
        int fd = real_##name args;                                      \
        if (fd >= 0) GUARDED(report_open(AT_FDCWD, tmpl, ACC_WRITE));            \
        return fd;                                                      \
    }
MKSTEMP_HOOK(mkstemp, (char *tmpl), (tmpl))
MKSTEMP_HOOK(mkstemp64, (char *tmpl), (tmpl))
MKSTEMP_HOOK(mkostemp, (char *tmpl, int flags), (tmpl, flags))
MKSTEMP_HOOK(mkostemp64, (char *tmpl, int flags), (tmpl, flags))
MKSTEMP_HOOK(mkstemps, (char *tmpl, int suffixlen), (tmpl, suffixlen))
MKSTEMP_HOOK(mkostemps, (char *tmpl, int suffixlen, int flags), (tmpl, suffixlen, flags))

int rename(const char *oldpath, const char *newpath) {
    REAL(rename, int (*)(const char *, const char *));
    int rc = real_rename(oldpath, newpath);
    if (rc == 0) GUARDED(report_open(AT_FDCWD, newpath, ACC_WRITE));
    return rc;
}

int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath) {
    REAL(renameat, int (*)(int, const char *, int, const char *));
    int rc = real_renameat(olddirfd, oldpath, newdirfd, newpath);
    if (rc == 0) GUARDED(report_open(newdirfd, newpath, ACC_WRITE));
    return rc;
}

int renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags) {
    REAL(renameat2, int (*)(int, const char *, int, const char *, unsigned int));
    int rc = real_renameat2(olddirfd, oldpath, newdirfd, newpath, flags);
    if (rc == 0) GUARDED(report_open(newdirfd, newpath, ACC_WRITE));
    return rc;
}

/* ---------- network ---------- */

int connect(int fd, const struct sockaddr *addr, socklen_t len) {
    REAL(connect, int (*)(int, const struct sockaddr *, socklen_t));
    GUARDED(report_connect(addr));
    return real_connect(fd, addr, len);
}
