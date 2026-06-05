#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <stdarg.h>
#include <time.h>

static FILE *log_fp = NULL;

static inline void log_init(const char *path) {
    if (path) log_fp = fopen(path, "w");
}

static inline void log_close(void) {
    if (log_fp) { fclose(log_fp); log_fp = NULL; }
}

static inline void log_msg(const char *file, int line, const char *fmt, ...) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    char prefix[64];
    snprintf(prefix, sizeof(prefix), "[%02ld:%02ld:%02ld.%03ld %s:%d] ",
             (ts.tv_sec % 86400) / 3600,
             (ts.tv_sec % 3600)  / 60,
              ts.tv_sec % 60,
              ts.tv_nsec / 1000000L,
              file, line);

    va_list args;

    va_start(args, fmt);
    fputs(prefix, stdout);
    vprintf(fmt, args);
    fflush(stdout);
    va_end(args);

    if (log_fp) {
        va_start(args, fmt);
        fputs(prefix, log_fp);
        vfprintf(log_fp, fmt, args);
        fflush(log_fp);
        va_end(args);
    }
}

#define LOG(fmt, ...) log_msg(__FILE__, __LINE__, fmt "\n", ##__VA_ARGS__)

#endif /* LOG_H */
