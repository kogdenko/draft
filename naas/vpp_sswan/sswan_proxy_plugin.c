#include <vnet/plugin/plugin.h>

#include <libnaas/ike_tunnel.h>
#include <libnaas/log.h>
#include <libnaas/utils.h>
#include <libnaas/vppapi.h>

struct sswan_proxy {
	const char *nats_server;
	int pod_id;
};

static vlib_log_class_t g_log;
static struct sswan_proxy g_sswan_proxy;

static void
vpp_log(int level, const char *s)
{
	int vlib_level;

	switch (level) {
	case LOG_EMERG:
		vlib_level = VLIB_LOG_LEVEL_EMERG;
		break;	
	case LOG_ALERT:
		vlib_level = VLIB_LOG_LEVEL_ALERT;
		break;
	case LOG_CRIT:
		vlib_level = VLIB_LOG_LEVEL_CRIT;
		break;
	case LOG_ERR:
		vlib_level = VLIB_LOG_LEVEL_ERR;
		break;
	case LOG_WARNING:
		vlib_level = VLIB_LOG_LEVEL_WARNING;
		break;
	case LOG_NOTICE:
		vlib_level = VLIB_LOG_LEVEL_NOTICE;
		break;
	case LOG_INFO:
		vlib_level = VLIB_LOG_LEVEL_INFO;
		break;
	case LOG_DEBUG:
		vlib_level = VLIB_LOG_LEVEL_DEBUG;
		break;
	default:
		assert(0);
		vlib_level = VLIB_LOG_LEVEL_EMERG;
	}

	vlib_log(vlib_level, g_log, "%s", s);
}

VLIB_PLUGIN_REGISTER () = {
	.version = "0.1",
	.description = "VPP Sswan Proxy Plugin",
};

static clib_error_t *
sswan_proxy_config(vlib_main_t *vm, unformat_input_t * input)
{
	unsigned int ike, api;

	g_sswan_proxy.pod_id = 0;
	g_sswan_proxy.nats_server = "localhost";
	ike = api = 0;

	while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT) {
		if (unformat(input, "pod %u", &g_sswan_proxy.pod_id)) {
		} else if (unformat(input, "nats_server %s", &g_sswan_proxy.nats_server)) {
		} else if (unformat(input, "ike %b", &ike)) {
		} else if (unformat(input, "api %b", &api)) {
		}
	}

	g_log = vlib_log_register_class("sswan_proxy", 0);

	naas_log_init(vpp_log);

	if (api) {
	}

	if (ike) {
	}

	return 0;
}

VLIB_CONFIG_FUNCTION(sswan_proxy_config, "sswan_proxy");

static clib_error_t *
sswan_proxy_init(vlib_main_t *vm)
{
	return 0;
}

VLIB_INIT_FUNCTION(sswan_proxy_init);
