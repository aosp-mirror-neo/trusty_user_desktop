/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define TLOG_TAG "hwrng_srv"

#include <assert.h>
#include <inttypes.h>
#include <lk/list.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uapi/err.h>

#include <hwcrypto/hwrng_dev.h>
#include <interface/hwrng/hwrng.h>
#include <lib/tipc/tipc.h>
#include <lib/tipc/tipc_srv.h>
#include <trusty_log.h>

#define HWRNG_SRV_NAME HWRNG_PORT
#define MAX_HWRNG_MSG_SIZE 4096

/* 0 means unlimited number of connections */
#define HWRNG_MAX_NUM_CHANNELS 0

struct hwrng_chan_ctx {
    struct tipc_event_handler evt_handler;
    struct list_node node;
    handle_t chan;
    size_t req_size;
    int error;
    bool send_blocked;
};

static uint8_t rng_data[MAX_HWRNG_MSG_SIZE];

static struct list_node hwrng_req_list = LIST_INITIAL_VALUE(hwrng_req_list);

/****************************************************************************/

/*
 *  Hexdump content of memory region
 */
static void _hexdump8(const void* ptr, size_t len) {
    uintptr_t address = (uintptr_t)ptr;
    size_t count;
    size_t i;

    for (count = 0; count < len; count += 16) {
        fprintf(stderr, "0x%08" PRIxPTR ": ", address);
        for (i = 0; i < MIN(len - count, 16); i++) {
            fprintf(stderr, "0x%02hhx ", *(const uint8_t*)(address + i));
        }
        fprintf(stderr, "\n");
        address += 16;
    }
}

/*
 * Handle HWRNG request queue
 */
static void hwrng_handle_req_queue(void) {
    int rc;
    struct hwrng_chan_ctx* ctx;
    struct hwrng_chan_ctx* temp;

    /* for all pending requests */
    bool more_requests;
    do {
        more_requests = false;
        list_for_every_entry_safe(&hwrng_req_list, ctx, temp,
                                  struct hwrng_chan_ctx, node) {
            if (ctx->error || ctx->send_blocked) {
                continue; /* can't service it right now */
            }

            size_t len = ctx->req_size;

            if (len > MAX_HWRNG_MSG_SIZE)
                len = MAX_HWRNG_MSG_SIZE;

            /* get hwrng data */
            rc = trusty_rng_hw_rand(rng_data, len);
            if (rc != NO_ERROR) {
                TLOGE("failed (%d) to get hwrng data\n", rc);
                ctx->error = rc;
                continue;
            }

            /* send reply */
            rc = tipc_send1(ctx->chan, rng_data, len);
            if (rc < 0) {
                if (rc == ERR_NOT_ENOUGH_BUFFER) {
                    /* mark it as send_blocked */
                    ctx->send_blocked = true;
                } else {
                    /* just close HWRNG request channel */
                    TLOGE("failed (%d) to send_reply\n", rc);
                    ctx->error = rc;
                }
                continue;
            }

            ctx->req_size -= len;

            if (ctx->req_size == 0) {
                /* remove it from pending list */
                list_delete(&ctx->node);
            } else {
                more_requests = true;
            }
        }
    } while (more_requests);
}

/*
 *  Read and queue HWRNG request message
 */
static int hwrng_chan_handle_msg(const struct tipc_port* port,
                                 handle_t chan,
                                 void* received_ctx) {
    int rc;
    struct hwrng_req req;

    struct hwrng_chan_ctx* ctx = (struct hwrng_chan_ctx*)received_ctx;

    assert(ctx);

    /* check for an error from a previous send attempt */
    if (ctx->error) {
        return ctx->error;
    }

    /* read request */
    rc = tipc_recv1(chan, sizeof(req), &req, sizeof(req));
    if (rc < 0) {
        TLOGE("failed (%d) to receive msg for chan %d\n", rc, chan);
        return rc;
    }

    /* check if we already have request in progress */
    if (list_in_list(&ctx->node)) {
        /* extend it */
        ctx->req_size += req.len;
    } else {
        /* queue it */
        ctx->req_size = req.len;
        list_add_tail(&hwrng_req_list, &ctx->node);
    }

    hwrng_handle_req_queue();

    return ctx->error;
}

/*
 * Create hwrng channel context
 */
static int hwrng_chan_ctx_create(const struct tipc_port* port,
                                 handle_t chan,
                                 const struct uuid* peer,
                                 void** ctx) {
    struct hwrng_chan_ctx* chan_ctx = calloc(1, sizeof(*chan_ctx));

    if (!chan_ctx) {
        return ERR_NO_MEMORY;
    }

    /* init channel state */
    chan_ctx->chan = chan;
    *ctx = chan_ctx;

    return NO_ERROR;
}

/*
 * Close specified hwrng channel context
 */
static void hwrng_chan_ctx_close(void* ctx_rcv) {
    struct hwrng_chan_ctx* ctx = (struct hwrng_chan_ctx*)ctx_rcv;

    if (list_in_list(&ctx->node))
        list_delete(&ctx->node);

    close(ctx->chan);
    free(ctx);
}

static int hwrng_handle_send_unblocked(const struct tipc_port* port,
                                       handle_t chan,
                                       void* ctx_v) {
    struct hwrng_chan_ctx* ctx = ctx_v;

    if (ctx->error) {
        return ctx->error;
    }

    ctx->send_blocked = false;

    hwrng_handle_req_queue();

    return ctx->error;
}

/*
 *  Initialize HWRNG services
 */
int hwrng_start_service(struct tipc_hset* hset) {
    int rc;

    TLOGD("Start HWRNG service\n");

    static struct tipc_port_acl acl = {
            .flags = IPC_PORT_ALLOW_TA_CONNECT,
            .uuid_num = 0,
            .uuids = NULL,
    };

    static struct tipc_port port = {
            .name = HWRNG_SRV_NAME,
            .msg_max_size = MAX_HWRNG_MSG_SIZE,
            .msg_queue_len = 1,
            .acl = &acl,
    };

    static struct tipc_srv_ops ops = {
            .on_message = hwrng_chan_handle_msg,
            .on_connect = hwrng_chan_ctx_create,
            .on_channel_cleanup = hwrng_chan_ctx_close,
            .on_send_unblocked = hwrng_handle_send_unblocked,
    };

    rc = hwrng_dev_init();
    if (rc != NO_ERROR) {
        TLOGE("Failed (%d) to initialize HWRNG device\n", rc);
        return rc;
    }

    return tipc_add_service(hset, &port, 1, HWRNG_MAX_NUM_CHANNELS, &ops);
}
