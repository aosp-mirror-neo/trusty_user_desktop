/*
 * Copyright (C) 2021 The Android Open Source Project
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

#define TLOG_TAG "keybox"

#include <assert.h>
#include <inttypes.h>
#include <lk/list.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uapi/err.h>

#include <interface/keybox/keybox.h>

#include <lib/tipc/tipc.h>
#include <trusty_log.h>

#include "keybox.h"
#include "srv.h"

/* 0 means unlimited number of connections */
#define KEYBOX_MAX_NUM_CHANNELS 0

struct keybox_chan_ctx {
    struct tipc_event_handler evt_handler;
    handle_t chan;
};

struct full_keybox_unwrap_req {
    struct keybox_unwrap_req unwrap_header;
    uint8_t wrapped_keybox[KEYBOX_MAX_SIZE];
};

struct full_keybox_unwrap_resp {
    struct keybox_resp header;
    struct keybox_unwrap_resp unwrap_header;
};

static int keybox_handle_unwrap(handle_t chan,
                                struct full_keybox_unwrap_req* req,
                                size_t req_size) {
    struct full_keybox_unwrap_resp rsp = {
            .header.cmd = KEYBOX_CMD_UNWRAP | KEYBOX_CMD_RSP_BIT,
    };

    uint8_t output[KEYBOX_MAX_SIZE];
    if (req_size < sizeof(req->unwrap_header)) {
        rsp.header.status = KEYBOX_STATUS_INVALID_REQUEST;
        goto out;
    }

    uint64_t computed_size;
    if (__builtin_add_overflow(req->unwrap_header.wrapped_keybox_len,
                               sizeof(req->unwrap_header), &computed_size)) {
        rsp.header.status = KEYBOX_STATUS_INVALID_REQUEST;
        goto out;
    }
    if (computed_size != req_size) {
        rsp.header.status = KEYBOX_STATUS_INVALID_REQUEST;
        goto out;
    }

    rsp.header.status = keybox_unwrap(
            req->wrapped_keybox, req->unwrap_header.wrapped_keybox_len, output,
            sizeof(output), (size_t*)&rsp.unwrap_header.unwrapped_keybox_len);
    if (rsp.header.status != KEYBOX_STATUS_SUCCESS) {
        goto out;
    }

    return tipc_send2(chan, &rsp, sizeof(rsp), output,
                      rsp.unwrap_header.unwrapped_keybox_len);

out:
    return tipc_send1(chan, &rsp, sizeof(rsp.header));
}

struct full_keybox_req {
    struct keybox_req header;
    union {
        struct full_keybox_unwrap_req unwrap;
    } cmd_header;
};

static int keybox_chan_handle_msg(const struct tipc_port* port,
                                  handle_t chan,
                                  void* ctx) {
    int rc;
    struct full_keybox_req req;
    enum keybox_status status = KEYBOX_STATUS_SUCCESS;
    rc = tipc_recv1(chan, sizeof(req.header), &req, sizeof(req));
    if (rc < 0) {
        TLOGE("Failed (%d) to receive Keybox message\n", rc);
        return KEYBOX_STATUS_INTERNAL_ERROR;
    }

    size_t cmd_specific_size = (size_t)rc - sizeof(req.header);
    switch (req.header.cmd) {
    case KEYBOX_CMD_UNWRAP:
        rc = keybox_handle_unwrap(chan, &req.cmd_header.unwrap,
                                  cmd_specific_size);
        break;
    default:
        TLOGE("Invalid Keybox command: %d\n", req.header.cmd);
        struct keybox_resp rsp;
        rsp.cmd = req.header.cmd | KEYBOX_CMD_RSP_BIT;
        rsp.status = KEYBOX_STATUS_INVALID_REQUEST;
        rc = tipc_send1(chan, &rsp, sizeof(rsp));
    }

    if (rc < 0) {
        status = KEYBOX_STATUS_INTERNAL_ERROR;
    }

    return status;
}

/*
 *  Initialize Keybox service
 */
int keybox_start_service(struct tipc_hset* hset) {
    TLOGD("Start Keybox service\n");

    // TODO: check why we are not restricting connections by uuid
    static struct tipc_port_acl acl = {
            .flags = IPC_PORT_ALLOW_TA_CONNECT,
            .uuid_num = 0,
            .uuids = NULL,
    };

    static struct tipc_port port = {
            .name = KEYBOX_PORT,
            .msg_max_size = sizeof(struct full_keybox_req),
            .msg_queue_len = 1,
            .acl = &acl,
    };
    static struct tipc_srv_ops ops = {
            .on_message = keybox_chan_handle_msg,
    };
    return tipc_add_service(hset, &port, 1, KEYBOX_MAX_NUM_CHANNELS, &ops);
}
