#include <vnet/error.h>

#include "log.h"
#include "strbuf.h"

static volatile int g_naas_log_level = LOG_NOTICE;
static naas_log_f g_naas_log_fn = naas_log_stdout;

void
naas_set_log_level(int log_level)
{
	NAAS_WRITE_ONCE(g_naas_log_level, log_level);
}

int
naas_get_log_level(void)
{
	return NAAS_READ_ONCE(g_naas_log_level);
}

int
naas_log_level_from_string(const char *s)
{
	if (!strcasecmp(s, "err")) {
		return LOG_ERR;
	} else if (!strcasecmp(s, "warning")) {
		return LOG_WARNING;
	} else if (!strcasecmp(s, "notice")) {
		return LOG_NOTICE;
	} else if (!strcasecmp(s, "info")) {
		return LOG_INFO;
	} else if (!strcasecmp(s, "debug")) {
		return LOG_DEBUG;
	} else {
		return -EINVAL;
	}
}

static void
naas_log_add_errno(struct naas_strbuf *sb, int err_num)
{
	naas_strbuf_addf(sb, " (%d:%s)", err_num, strerror(err_num));
}

static void
naas_log_add_vnet_error(struct naas_strbuf *sb, int err_num)
{
	switch (-err_num) {
#define _(a, b, c) \
	case b: \
		naas_strbuf_addf(sb, " (VNET_ERR_%s:%s)", #a, c); \
		break;
	foreach_vnet_error
#undef _

	default:
		naas_strbuf_addf(sb, "(VNET_ERR_%d:?)", -err_num);
		break;
	}
}

// TODO: As pointer to function
/*static void
naas_log_add_nats_error(struct naas_strbuf *sb, int s)
{
	naas_strbuf_adds(sb, natsStatus_GetText(s));
}*/

void
naas_log_add_err(struct naas_strbuf *sb, int err)
{
	int num, type;

	num = naas_err_get_num(err);
	type = naas_err_get_type(err);
	naas_strbuf_addf(sb, "%d:", num);
	if (num) {
		switch (type) {
		case NAAS_ERR_ERRNO:
			naas_log_add_errno(sb, num);
			break;

		case NAAS_ERR_VNET:
			naas_log_add_vnet_error(sb, num);
			break;

		case NAAS_ERR_NATS:
//			naas_log_add_nats_error(sb, num);
			break;

		default:
			naas_die(0, "Unknown error type (%d)", type);
		}
	}
}

void
naas_log_flush(int level, struct naas_strbuf *sb)
{
	const char *s;
	const char *msg = " ~ log truncated...";
	int len;


	if (sb->sb_len > sb->sb_cap) {
		len = strlen(msg);
		memcpy(sb->sb_buf + sb->sb_cap - (len + 1), msg, len);
	}
	s = naas_strbuf_cstr(sb);
	(*g_naas_log_fn)(level, s);
}

void
naas_log_init(naas_log_f log_fn)
{
	g_naas_log_fn = log_fn;
	naas_logf(naas_get_log_level(), 0, "Logging started");
}

void
naas_log_syslog(int level, const char *s)
{
	syslog(level, "%s", s);
}

void
naas_log_stdout(int level, const char *s)
{
	FILE *stream;

	if (level <= LOG_ERR) {
		stream = stderr;
	} else {
		stream = stdout;
	}
	fprintf(stream, "%s\n", s);
}

void
naas_vlogf(int level, int err, const char *format, va_list ap)
{
	char log_buf[NAAS_LOGBUFSZ];
	struct naas_strbuf sb;

	if (NAAS_READ_ONCE(g_naas_log_level) < level) {
		return;
	}
	naas_strbuf_init(&sb, log_buf, sizeof(log_buf));
	naas_strbuf_vaddf(&sb, format, ap);
	if (err > 0) {
		naas_strbuf_adds(&sb, " (");
		naas_log_add_err(&sb, err);
		naas_strbuf_adds(&sb, ")");
	}
	naas_log_flush(level, &sb);
}

void
naas_logf(int level, int err, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	naas_vlogf(level, err, format, ap);
	va_end(ap);
}

void
naas_log_hexdump_ascii(int level, const void * data, int count)
{
	char log_buf[NAAS_LOGBUFSZ];
	struct naas_strbuf sb;

	if (NAAS_READ_ONCE(g_naas_log_level) < level) {
		printf("BBB %d %d\n", g_naas_log_level, level  );

		return;
	}

	naas_strbuf_init(&sb, log_buf, sizeof(log_buf));
	naas_strbuf_hexdump_ascii(&sb, data, count);
	naas_log_flush(level, &sb);
}

void
naas_die(int err, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	naas_vlogf(LOG_CRIT, err, format, ap);
	va_end(ap);

	abort();
}

