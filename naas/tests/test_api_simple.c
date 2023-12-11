#include <libnaas/log.h>
#include <libnaas/utils.h>
#include <libnaas/vppapi.h>
#include <libnaas/vppapi_rpc.h>

static int g_pod = -1;
static const char *g_nats_server = "localhost";
static struct naas_vppapi_rpc g_rpc;
static struct naas_vppapi_vac g_vac;

static struct naas_vppapi_client *
test_connect()
{
	int rc;

	if (g_pod < 0) {
		naas_assert(rc, (rc = naas_vppapi_vac_init(&g_vac, "naas_test")) == 0);
		return &g_vac.vac_base;
	} else {
		naas_assert(rc, (rc = naas_vppapi_rpc_init(&g_rpc, g_pod, g_nats_server)) == 0);
		return &g_rpc.rpc_base;
	}
}

static int
test_show_version(struct naas_vppapi_client *vppapicli)
{
	int rc;
	vl_api_show_version_reply_t ver;

	rc = naas_vppapi_show_version(vppapicli, &ver);

	if (rc == 0) {
		printf("%s %s %s %s\n", ver.program, ver.version,
				ver.build_date, ver.build_directory);
	}

	return rc;
}

void
test_1(void)
{
	struct naas_vppapi_client *vppapicli;

	vppapicli = test_connect();
	test_show_version(vppapicli);
	naas_vppapi_deinit(vppapicli);

	printf("Press key...\n");
	getc(stdin);

	vppapicli = test_connect();
	test_show_version(vppapicli);
	naas_vppapi_deinit(vppapicli);
}

int
test_2(void)
{
	struct naas_vppapi_client *vppapicli;

	vppapicli = test_connect();

	for (;;) {
		test_show_version(vppapicli);
		sleep(2);
	}
}

int
main(int argc, char **argv)
{
	int opt, long_option_index;
	const char *long_option_name;
	struct option long_options[] = {
		{"help", no_argument, 0, 'h' },
		{"pod", required_argument, 0, 0 },
		{"nats-server", required_argument, 0, 0 },
	};

	while ((opt = getopt_long(argc, argv, "h",
			long_options, &long_option_index)) != -1) {
		switch (opt) {
		case 0:
			long_option_name = long_options[long_option_index].name;
			if (!strcmp(long_option_name, "pod")) {
				g_pod = strtoul(optarg, NULL, 10);
			} else if (!strcmp(long_option_name, "nats-server")) {
				g_nats_server = optarg;
			}
			break;
		}
	}

	naas_log_init(naas_log_stdout);
	naas_set_log_level(LOG_DEBUG);

	test_2();

	return EXIT_SUCCESS;
}
