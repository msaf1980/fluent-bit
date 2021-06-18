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
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_config_map.h>
#include <msgpack.h>

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>

#include "statsd.h"
#include "statsd_conf.h"

static int cb_statsd_init(struct flb_output_instance *ins,
                       struct flb_config *config, void *data)
{
    struct flb_out_statsd *ctx = NULL;
    (void) data;

    ctx = flb_statsd_conf_create(ins, config);
    if (!ctx) {
        return -1;
    }

    /* Set the plugin context */
    flb_output_set_context(ins, ctx);

    return 0;
}

#define STATSD_TIMING "timing"
#define STATSD_INCREMENT "increment"

#define LL_MAX_LEN 21

static long long str2ll_n(const char *s, size_t n) {
    long long result = 0;
    char plus = 1;
    const char *end = s + n;
    if (n > LL_MAX_LEN) {
        errno = ERANGE;
        return LONG_MAX;
    }
    while (*s == '-' || *s == '+' || *s == ' ') {
        if (*s == '-')
            plus = -1;
        s++;
    }
  while (s < end && *s >= '0' && *s <= '9')
  {
      result = (result * 10) + ((*s) - '0');
      s++;
  }
  if (s < end && *s != '\0') {
      errno = EINVAL;
      return LONG_MAX;
  }
  errno = 0;
  return (result * plus);
}

static size_t ll2str(char *s, long long value) {
    char *p, aux;
    unsigned long long v;
    size_t l;

    /* Generate the string representation, this method produces
     * an reversed string. */
    v = (value < 0) ? -value : value;
    p = s;
    do {
        *p++ = '0'+(v%10);
        v /= 10;
    } while(v);
    if (value < 0) *p++ = '-';

    /* Compute length and add null term. */
    l = p-s;
    *p = '\0';

    /* Reverse the string. */
    p--;
    while(s < p) {
        aux = *s;
        *s = *p;
        *p = aux;
        s++;
        p--;
    }
    return l;
}

static int statsd_format(struct flb_config *config,
                                struct flb_out_statsd *ctx,
                                msgpack_object* o,
                                void *out_data, size_t *out_size)
{
    char *d = out_data;
    size_t max_size = *out_size;

    *out_size = 0;

    msgpack_object* p = o->via.array.ptr;
    msgpack_object* const pend = o->via.array.ptr + o->via.array.size;
    for(; p < pend; ++p) {
        if (p->type != MSGPACK_OBJECT_MAP) {
            continue;
        }
        if(p->via.map.size != 0) {
            msgpack_object_kv* pv = p->via.map.ptr;
            msgpack_object_kv* const pendv = p->via.map.ptr + p->via.map.size;
            do {
                if (pv->key.type == MSGPACK_OBJECT_STR) {
                    long long v;
                    if (pv->key.via.str.size == sizeof(STATSD_INCREMENT) - 1 &&
                        memcmp(pv->key.via.str.ptr, STATSD_INCREMENT, pv->key.via.str.size) == 0) {
                        if (pv->val.type == MSGPACK_OBJECT_STR) {
                            v = str2ll_n(pv->val.via.str.ptr, pv->val.via.str.size);
                            if (v == LONG_MAX && errno) {
                                char tmpbuf[1024], *pbuf;
                                memcpy(tmpbuf, pv->key.via.str.ptr, pv->key.via.str.size);
                                pbuf = tmpbuf + pv->key.via.str.size;
                                *pbuf++ = '=';
                                memcpy(pbuf, pv->val.via.str.ptr, pv->val.via.str.size);
                                pbuf[pv->val.via.str.size] = '\0';
                                flb_plg_error(ctx->ins, "format error (value not a number): '%s'", tmpbuf);
                                continue;
                            }
                        } else if (pv->val.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
                            v = pv->val.via.i64;
                        }
                        if (v < 0) {
                            char tmpbuf[1024], *pbuf;
                            memcpy(tmpbuf, pv->key.via.str.ptr, pv->key.via.str.size);
                            pbuf = tmpbuf + pv->key.via.str.size;
                            *pbuf++ = '=';
                            ll2str(pbuf, v);
                            flb_plg_error(ctx->ins, "format error (value is a negative number): '%s'", tmpbuf);
                            continue;
                        }
                        *out_size += ctx->metric_len + pv->key.via.str.size + LL_MAX_LEN + 2 + 3;
                        if (*out_size > max_size)
                            return -1;
                        memcpy(d, ctx->metric, ctx->metric_len);
                        d += ctx->metric_len;
                        *d++ = '.';
                        memcpy(d, pv->key.via.str.ptr, pv->key.via.str.size);
                        d += pv->key.via.str.size;
                        *d++ = ':';
                        d += ll2str(d, v);
                        memcpy(d, "|c\n", 3);
                        d += 3;
                    } else if (pv->key.via.str.size == sizeof(STATSD_TIMING) - 1 &&
                        memcmp(pv->key.via.str.ptr, STATSD_TIMING, pv->key.via.str.size) == 0) {
                        if (pv->val.type == MSGPACK_OBJECT_STR) {
                            v = str2ll_n(pv->val.via.str.ptr, pv->val.via.str.size);
                            if (v == LONG_MAX && errno) {
                                char tmpbuf[1024], *pbuf;
                                memcpy(tmpbuf, pv->key.via.str.ptr, pv->key.via.str.size);
                                pbuf = tmpbuf + pv->key.via.str.size;
                                *pbuf++ = '=';
                                memcpy(pbuf, pv->val.via.str.ptr, pv->val.via.str.size);
                                pbuf[pv->val.via.str.size] = '\0';
                                flb_plg_error(ctx->ins, "format error (value not a number): '%s'", tmpbuf);
                                continue;
                            }
                        } else if (pv->val.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
                            v = pv->val.via.i64;
                        }
                        if (v < 0) {
                            char tmpbuf[1024], *pbuf;
                            memcpy(tmpbuf, pv->key.via.str.ptr, pv->key.via.str.size);
                            pbuf = tmpbuf + pv->key.via.str.size;
                            *pbuf++ = '=';
                            ll2str(pbuf, v);
                            flb_plg_error(ctx->ins, "format error (value is a negative number): '%s'", tmpbuf);
                            continue;
                        }
                        *out_size += ctx->metric_len + pv->key.via.str.size + LL_MAX_LEN + 2 + 4;
                        if (*out_size > max_size)
                            return -1;
                        memcpy(d, ctx->metric, ctx->metric_len);
                        d += ctx->metric_len;
                        *d++ = '.';
                        memcpy(d, pv->key.via.str.ptr, pv->key.via.str.size);
                        d += pv->key.via.str.size;
                        *d++ = ':';
                        d += ll2str(d, v);
                        memcpy(d, "|ms\n", 4);
                        d += 4;
                    }
                }
            } while (++pv < pendv);
        }
    }

    /* fwrite((char *) out_data, *out_size, 1, stdout); */
    return 0;
}

static void cb_statsd_flush(const void *data, size_t bytes,
                         const char *tag, int tag_len,
                         struct flb_input_instance *i_ins,
                         void *out_context,
                         struct flb_config *config)
{
    int ret = FLB_OK;
    size_t bytes_sent;
    struct flb_upstream *u;
    struct flb_upstream_conn *u_conn;
    struct flb_out_statsd *ctx = out_context;
    char out_data[1024];
    size_t out_bytes;
    msgpack_unpacked result;
    size_t off = 0;
    (void) i_ins;

    /* Get upstream context and connection */
    u = ctx->u;
    u_conn = flb_upstream_conn_get(u);
    if (!u_conn) {
        flb_plg_warn(ctx->ins, "no upstream connections available to %s:%i",
                      u->host, u->port);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Iterate the original buffer and perform adjustments */
    msgpack_unpacked_init(&result);

    while ((ret = msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS)) {
        if (result.data.type != MSGPACK_OBJECT_ARRAY) {
            continue;
        }
        out_bytes = sizeof(out_data);
        if (statsd_format(config, ctx, &result.data, out_data, &out_bytes) >= 0) {
            if (flb_io_net_write(u_conn, out_data, out_bytes, &bytes_sent) == -1) {
                flb_errno();
                ret = FLB_RETRY;
                break;
            }
        }
    }

    flb_upstream_conn_release(u_conn);
    msgpack_unpacked_destroy(&result);
    FLB_OUTPUT_RETURN(ret);
}

static int cb_statsd_exit(void *data, struct flb_config *config)
{
    struct flb_out_statsd *ctx = data;

    flb_statsd_conf_destroy(ctx);
    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
        FLB_CONFIG_MAP_STR, "metric", NULL,
        0, FLB_TRUE, offsetof(struct flb_out_statsd, metric),
        "Specify an metric name for target statsd server, e.g: test.hostname.latency"
    },
    /* EOF */
    {0}
};

/* Plugin reference */
struct flb_output_plugin out_statsd_plugin = {
    .name           = "statsd",
    .description    = "Statsd Output",
    .cb_init        = cb_statsd_init,
    .cb_flush       = cb_statsd_flush,
    .cb_exit        = cb_statsd_exit,
    .config_map     = config_map,
    .flags          = FLB_OUTPUT_NET,
};
