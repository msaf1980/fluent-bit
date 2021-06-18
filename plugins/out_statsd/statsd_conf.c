/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_pack.h>

#include "statsd.h"
#include "statsd_conf.h"

struct flb_out_statsd *flb_statsd_conf_create(struct flb_output_instance *ins,
                                        struct flb_config *config)
{
    int ret;
    int io_flags = 0;
    const char *tmp;
    struct flb_upstream *upstream;
    struct flb_out_statsd *ctx = NULL;

    /* Allocate plugin context */
    ctx = flb_calloc(1, sizeof(struct flb_out_statsd));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ins = ins;

    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_statsd_conf_destroy(ctx);
        return NULL;
    }

    tmp = flb_output_get_property("metric", ins);
    if (tmp) {
        ctx->metric_len = strlen(tmp);
    } else {
        flb_plg_error(ctx->ins, "'metric' is a required parameter");
        flb_statsd_conf_destroy(ctx);
        return NULL;
    }

    /* Set default network configuration if not set */
    flb_output_net_default("127.0.0.1", 8125, ins);

    io_flags = FLB_IO_UDP;

    if (ins->host.ipv6 == FLB_TRUE) {
        io_flags |= FLB_IO_IPV6;
    }

    /* Upstream context */
    upstream = flb_upstream_create(config,
                                   ins->host.name,
                                   ins->host.port,
                                   io_flags, NULL);
    if (!upstream) {
        flb_plg_error(ctx->ins, "could not create upstream context");
        flb_free(ctx);
        return NULL;
    }

    ctx->u = upstream;
    flb_output_upstream_set(ctx->u, ins);

    ctx->host = ins->host.name;
    ctx->port = ins->host.port;

    return ctx;
}

void flb_statsd_conf_destroy(struct flb_out_statsd *ctx)
{
    if (!ctx) {
        return;
    }

    if (ctx->u) {
        flb_upstream_destroy(ctx->u);
    }

    // flb_free(ctx->metric);
    // flb_free(ctx->timing);
    // flb_free(ctx->increment);
    flb_free(ctx);
    ctx = NULL;
}
