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

#define TLOG_TAG "hwcrypto_srv"

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <uapi/err.h>

#include <lib/tipc/tipc.h>
#include <lk/err_ptr.h>
#include <trusty_log.h>

#include "hwkey_srv_priv.h"

/*
 *  Main application event loop
 */
int run_hwkey(uint8_t* encrypt, size_t encrypt_size, uint8_t* attest,
        size_t attest_size, uint8_t* auth_token_key_seed,
        size_t auth_token_key_seed_size, int32_t rollback_version,
        int32_t running_version) {
    int rc;
    struct tipc_hset* hset;

    TLOGD("Initializing\n");

    hset = tipc_hset_create();
    if (IS_ERR(hset)) {
        rc = PTR_ERR(hset);
        TLOGE("tipc_hset_create failed (%d)\n", rc);
        goto out;
    }

    /* initialize service providers */
    rc = hwkey_init_srv_provider(hset, encrypt, encrypt_size, attest,
            attest_size, auth_token_key_seed, auth_token_key_seed_size,
            rollback_version, running_version);
    if (rc != NO_ERROR) {
        TLOGE("Failed (%d) to initialize HwKey service\n", rc);
        goto out;
    }

    TLOGD("enter main event loop\n");

    /* enter main event loop */
    rc = tipc_run_event_loop(hset);

out:
    return rc;
}
