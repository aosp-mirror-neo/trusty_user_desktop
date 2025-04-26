/*
 * Copyright (C) 2025 The Android Open Source Project
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

use hwbcc::srv::HwBccService;
use pvmdice::PvmDice;
use tipc::{Manager, PortCfg};
use trusty_std::rc::Rc;
use vmm_obj::get_vmm_obj;

const HWBCC_PORT_NAME: &str = "com.android.trusty.hwbcc";

fn main() {
    trusty_log::init();
    let dice = get_vmm_obj(c"google,open-dice").expect("Could not get DICE chain");

    let pvmdice = Rc::new(PvmDice::try_new(&dice).expect("Could not initialize PvmDice"));

    let service = HwBccService::new(pvmdice);

    let cfg = PortCfg::new(HWBCC_PORT_NAME).expect("Could not create port config");
    let buffer = [0u8; 4096];
    Manager::<_, _, 1, 1>::new(service, cfg, buffer)
        .expect("Could not create service manager")
        .run_event_loop()
        .expect("hwbcc event loop failed");
}
