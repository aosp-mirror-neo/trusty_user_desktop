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

#include <hwcrypto/hwrng_dev.h>
#include <lib/tipc/tipc.h>
#include <lk/err_ptr.h>
#include <trusty_log.h>

#include "hwkey_srv_priv.h"
#include "hwrng_srv_priv.h"

#include "keybox/srv.h"

/*
 *  Main application event loop
 */
int main(void) {
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
#if WITH_HWCRYPTO_HWRNG
    rc = hwrng_start_service(hset);
    if (rc != NO_ERROR) {
        TLOGE("Failed (%d) to initialize HWRNG service\n", rc);
        goto out;
    }
#endif

    /*rc = hwkey_init_srv_provider(hset);*/
    /*if (rc != NO_ERROR) {*/
        /*TLOGE("Failed (%d) to initialize HwKey service\n", rc);*/
        /*goto out;*/
    /*}*/

#if defined(WITH_FAKE_KEYBOX)
    rc = keybox_start_service(hset);
    if (rc != NO_ERROR) {
        TLOGE("Failed (%d) to initialize Keybox service\n", rc);
        goto out;
    }
#endif

    TLOGD("enter main event loop\n");

    /* enter main event loop */
    rc = tipc_run_event_loop(hset);

out:
    return rc;
}
