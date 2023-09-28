pub const IAS_QUOTE_STATUS_LEVEL_1: &'static [&str] = &[
    "OK",
];
pub const IAS_QUOTE_STATUS_LEVEL_2: &'static [&str] = &[
    "SW_HARDENING_NEEDED",
];
pub const IAS_QUOTE_STATUS_LEVEL_3: &'static [&str] = &[
    "CONFIGURATION_NEEDED",
    "CONFIGURATION_AND_SW_HARDENING_NEEDED",
];
// LEVEL 4 is LEVEL 3 with advisors which not included in whitelist
pub const IAS_QUOTE_STATUS_LEVEL_5: &'static [&str] = &[
    "GROUP_OUT_OF_DATE",
];
pub const IAS_QUOTE_ADVISORY_ID_WHITELIST: &'static [&str] = &[
    "INTEL-SA-00334", "INTEL-SA-00219",
    "INTEL-SA-00381", "INTEL-SA-00389",
];
