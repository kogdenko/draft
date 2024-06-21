#ifndef NAAS_COMMON_LOG_H
#define NAAS_COMMON_LOG_H

#include "utils.h"

#define NAAS_LOGBUFSZ 65536

struct naas_strbuf;

typedef void (*naas_log_f)(int, const char *);

extern naas_log_f naas_log_syslog_fn;

void naas_set_log_level(int);
int naas_get_log_level(void);
int naas_log_level_from_string(const char *);
void naas_log_add_err(struct naas_strbuf *, int);
void naas_log_flush(int level, struct naas_strbuf *);
void naas_log_init(naas_log_f);
void naas_log_syslog(int, const char *);
void naas_log_stdout(int, const char *);

void naas_vlogf(int, int, const char *, va_list);

void naas_logf(int, int, const char *, ...)
	__attribute__((format(printf, 3, 4)));

void naas_log_hexdump_ascii(int level, const void *, int);

void naas_die(int, const char *, ...)
	__attribute__((format(printf, 2, 3)));

#endif // NAAS_COMMON_LOG_H
