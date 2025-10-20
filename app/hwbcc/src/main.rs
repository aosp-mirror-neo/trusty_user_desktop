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
use tipc::{Manager, PortCfg, Uuid};
use trusty_std::rc::Rc;
use vmm_obj::get_vmm_obj;

const HWBCC_PORT_NAME: &str = "com.android.trusty.hwbcc";

const HWBCC_ACCESSIBLE_UUIDS: [Uuid; 2] = [
    // KeyMint TEE UUID
    Uuid::new(0x5f902ace, 0x5e5c, 0x4cd8, [0xae, 0x54, 0x87, 0xb8, 0x8c, 0x22, 0xdd, 0xaf]),
    // StrongBox KeyMint UUID
    Uuid::new(0xc6b5b730, 0xf21c, 0x480b, [0xad, 0x6f, 0xcc, 0x19, 0x76, 0x80, 0xb7, 0x6c]),
];

fn log_formatter(record: &log::Record) -> String {
    // line number should be present, so keeping it simple by just returning a 0.
    let line = record.line().unwrap_or(0);
    let file = record.file().unwrap_or("unknown file");
    format!("{}: {}:{} {}\n", record.level(), file, line, record.args())
}

fn main() {
    let config = trusty_log::TrustyLoggerConfig::default()
        .with_min_level(log::Level::Trace)
        .format(log_formatter);
    trusty_log::init_with_config(config);

    let dice = get_vmm_obj(c"google,open-dice").expect("Could not get DICE chain");
    let pvmdice = Rc::new(PvmDice::try_new(&dice).expect("Could not initialize PvmDice"));
    let service = HwBccService::new(pvmdice);

    let cfg = PortCfg::new(HWBCC_PORT_NAME)
        .expect("Could not create port config")
        .allow_ta_connect()
        .allowed_uuids(&HWBCC_ACCESSIBLE_UUIDS);
    let buffer = [0u8; 4096];
    Manager::<_, _, 1, 1>::new(service, cfg, buffer)
        .expect("Could not create service manager")
        .run_event_loop()
        .expect("hwbcc event loop failed");
}
