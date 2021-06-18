/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit.h>
#include "flb_tests_runtime.h"

/* Test data */
#include "data/statsd/json_statsd_invalid.h" /* JSON_STATSD_INVALID */
// #include "data/common/json_long.h"    /* JSON_LONG    */
#include "data/statsd/json_statsd.h"   /* JSON_STATSD   */

// static void statsd_server() {
//     flb_sockfd_t flb_net_server_udp(const char *port, const char *listen_addr);
// }

void flb_test_statsd_invalid(void)
{
    int i;
    int ret;
    int total;
    int bytes;
    char *p = (char *) JSON_STATSD_INVALID;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "statsd", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "metric", "test.latency", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    total = 0;
    for (i = 0; i < (int) sizeof(JSON_STATSD_INVALID) - 1; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p + i, 1);
        TEST_CHECK(bytes == 1);
        if (bytes < 0) break;
        total++;
    }

    sleep(1); /* waiting flush */

    flb_stop(ctx);
    flb_destroy(ctx);
}
void flb_test_statsd(void)
{
    int i;
    int ret;
    int total;
    int bytes;
    char *p = (char *) JSON_STATSD;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "statsd", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "metric", "test.latency", NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    total = 0;
    for (i = 0; i < (int) sizeof(JSON_STATSD) - 1; i++) {
        bytes = flb_lib_push(ctx, in_ffd, p + i, 1);
        TEST_CHECK(bytes == 1);
        if (bytes < 0) break;
        total++;
    }

    sleep(1); /* waiting flush */

    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Test list */
TEST_LIST = {
    {"statsd_invalid",    flb_test_statsd_invalid    },
    {"statsd",            flb_test_statsd            },
    {NULL, NULL}
};
