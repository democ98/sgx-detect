#![crate_name = "enclaveapp"]
#![crate_type = "staticlib"]

#![warn(unused_imports)]
#![warn(unused_extern_crates)]

#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

#[cfg(not(target_env = "sgx"))]
#[macro_use] extern crate sgx_tstd as std;

#[macro_use] extern crate lazy_static;

use sgx_types::*;
use sgx_tse::*;
use sgx_tcrypto::*;
use sgx_rand::*;

use sgx_types::sgx_status_t;

use crate::std::prelude::v1::*;
use crate::std::ptr;
use crate::std::str;
use crate::std::string::String;
use crate::std::vec::Vec;
use itertools::Itertools;
use parity_scale_codec::{Encode, Decode};
use secp256k1::{SecretKey, PublicKey};
use serde_json::Value;

use std::time::{Duration, Instant};
use http_req::request::{Request, Method};

mod hex;
mod cert;
mod pib;
mod constants;

use constants::*;

const IAS_SPID_STR: &str = env!("IAS_SPID");
const IAS_API_KEY_STR: &str = env!("IAS_API_KEY");

pub const IAS_HOST:&'static str = env!("IAS_HOST");
pub const IAS_SIGRL_ENDPOINT:&'static str = env!("IAS_SIGRL_ENDPOINT");
pub const IAS_REPORT_ENDPOINT:&'static str = env!("IAS_REPORT_ENDPOINT");

extern "C" {
    pub fn ocall_sgx_init_quote ( ret_val : *mut sgx_status_t,
                                  ret_ti  : *mut sgx_target_info_t,
                                  ret_gid : *mut sgx_epid_group_id_t) -> sgx_status_t;
    pub fn ocall_get_quote (ret_val            : *mut sgx_status_t,
                            p_sigrl            : *const u8,
                            sigrl_len          : u32,
                            p_report           : *const sgx_report_t,
                            quote_type         : sgx_quote_sign_type_t,
                            p_spid             : *const sgx_spid_t,
                            p_nonce            : *const sgx_quote_nonce_t,
                            p_qe_report        : *mut sgx_report_t,
                            p_quote            : *mut u8,
                            maxlen             : u32,
                            p_quote_len        : *mut u32) -> sgx_status_t;
}

lazy_static! {
    static ref IAS_SPID: sgx_spid_t = {
        hex::decode_spid(IAS_SPID_STR)
    };

    static ref IAS_API_KEY: String = {
        let stringify_key: String = IAS_API_KEY_STR.into();
        stringify_key.trim_end().to_owned()
    };
}

pub fn get_sigrl_from_intel(gid : u32) -> Vec<u8> {
    // println!("get_sigrl_from_intel fd = {:?}", fd);
    //let sigrl_arg = SigRLArg { group_id : gid };
    //let sigrl_req = sigrl_arg.to_httpreq();
    let ias_key = IAS_API_KEY.clone();

    let mut res_body_buffer = Vec::new(); //container for body of a response
    let timeout = Some(Duration::from_secs(8));

    let url = format!("https://{}{}/{:08x}", IAS_HOST, IAS_SIGRL_ENDPOINT, gid).parse().unwrap();
    let res = Request::new(&url)
        .header("Connection", "Close")
        .header("Ocp-Apim-Subscription-Key", &ias_key)
        .timeout(timeout)
        .connect_timeout(timeout)
        .read_timeout(timeout)
        .send(&mut res_body_buffer)
        .unwrap();

    // parse_response_sigrl

    let status_code = u16::from(res.status_code());
    if status_code != 200 {
        let msg =
            match status_code {
                401 => "Unauthorized Failed to authenticate or authorize request.",
                404 => "Not Found GID does not refer to a valid EPID group ID.",
                500 => "Internal error occurred",
                503 => "Service is currently not able to process the request (due to
                a temporary overloading or maintenance). This is a
                temporary state – the same request can be repeated after
                some time. ",
                _ => "Unknown error occured",
            };

        println!("{}", msg);
        // TODO: should return Err
        panic!("status code not 200");
    }

    if res.content_len() != None && res.content_len() != Some(0) {
        let res_body = res_body_buffer.clone();
        let encoded_sigrl = str::from_utf8(&res_body).unwrap();
        println!("Base64-encoded SigRL: {:?}", encoded_sigrl);

        return base64::decode(encoded_sigrl).unwrap()
    }

    Vec::new()
}

// TODO: support pse
pub fn get_report_from_intel(quote : Vec<u8>) -> (String, String, String) {
    // println!("get_report_from_intel fd = {:?}", fd);
    let encoded_quote = base64::encode(&quote[..]);
    let encoded_json = format!("{{\"isvEnclaveQuote\":\"{}\"}}\r\n", encoded_quote);

    let ias_key = IAS_API_KEY.clone();

    let mut res_body_buffer = Vec::new(); //container for body of a response
    let timeout = Some(Duration::from_secs(8));

    let url = format!("https://{}{}", IAS_HOST, IAS_REPORT_ENDPOINT).parse().unwrap();
    let res = Request::new(&url)
        .header("Connection", "Close")
        .header("Content-Type", "application/json")
        .header("Content-Length", &encoded_json.len())
        .header("Ocp-Apim-Subscription-Key", &ias_key)
        .method(Method::POST)
        .body(encoded_json.as_bytes())
        .timeout(timeout)
        .connect_timeout(timeout)
        .read_timeout(timeout)
        .send(&mut res_body_buffer)
        .unwrap();

    let status_code = u16::from(res.status_code());
    if status_code != 200 {
        let msg =
            match status_code {
                401 => "Unauthorized Failed to authenticate or authorize request.",
                404 => "Not Found GID does not refer to a valid EPID group ID.",
                500 => "Internal error occurred",
                503 => "Service is currently not able to process the request (due to
                a temporary overloading or maintenance). This is a
                temporary state – the same request can be repeated after
                some time. ",
                _ => "Unknown error occured",
            };

        println!("{}", msg);
        // TODO: should return Err
        panic!("status code not 200");
    }

    let content_len =
        match res.content_len() {
            Some(len) => len,
            _ => {
                println!("content_length not found");
                0
            }
        };

    if content_len == 0 {
        // TODO: should return Err
        panic!("don't know how to handle content_length is 0");
    }

    let attn_report = String::from_utf8(res_body_buffer).unwrap();
    let sig = res.headers().get("X-IASReport-Signature").unwrap().to_string();
    let mut cert = res.headers().get("X-IASReport-Signing-Certificate").unwrap().to_string();

    // Remove %0A from cert, and only obtain the signing cert
    cert = cert.replace("%0A", "");
    cert = cert::percent_decode(cert);
    let v: Vec<&str> = cert.split("-----").collect();
    let sig_cert = v[2].to_string();

    // len_num == 0
    (attn_report, sig, sig_cert)
}

fn as_u32_le(array: &[u8; 4]) -> u32 {
    ((array[0] as u32) <<  0) +
        ((array[1] as u32) <<  8) +
        ((array[2] as u32) << 16) +
        ((array[3] as u32) << 24)
}

#[allow(const_err)]
pub fn create_attestation_report(data: &[u8], sign_type: sgx_quote_sign_type_t) -> Result<(String, String, String), sgx_status_t> {
    let data_len = data.len();
    if data_len > SGX_REPORT_DATA_SIZE {
        panic!("data length over 64 bytes");
    }

    // Workflow:
    // (1) ocall to get the target_info structure (ti) and epid group id (eg)
    // (1.5) get sigrl
    // (2) call sgx_create_report with ti+data, produce an sgx_report_t
    // (3) ocall to sgx_get_quote to generate (*mut sgx-quote_t, uint32_t)

    // (1) get ti + eg
    let mut ti : sgx_target_info_t = sgx_target_info_t::default();
    let mut eg : sgx_epid_group_id_t = sgx_epid_group_id_t::default();
    let mut rt : sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;

    let res = unsafe {
        ocall_sgx_init_quote(&mut rt as *mut sgx_status_t,
                             &mut ti as *mut sgx_target_info_t,
                             &mut eg as *mut sgx_epid_group_id_t)
    };

    // println!("eg = {:?}", eg);

    if res != sgx_status_t::SGX_SUCCESS {
        return Err(res);
    }

    if rt != sgx_status_t::SGX_SUCCESS {
        return Err(rt);
    }

    let eg_num = as_u32_le(&eg);

    // Now sigrl_vec is the revocation list, a vec<u8>
    let sigrl_vec : Vec<u8> = get_sigrl_from_intel(eg_num);

    // (2) Generate the report
    // Fill data into report_data
    let mut report_data: sgx_report_data_t = sgx_report_data_t::default();
    report_data.d[..data_len].clone_from_slice(data);

    let rep = match rsgx_create_report(&ti, &report_data) {
        Ok(r) =>{
            // println!("Report creation => success {:?}", r.body.mr_signer.m);
            Some(r)
        },
        Err(e) =>{
            println!("Report creation => failed {:?}", e);
            None
        },
    };

    let mut quote_nonce = sgx_quote_nonce_t { rand : [0;16] };
    let mut os_rng = os::SgxRng::new().unwrap();
    os_rng.fill_bytes(&mut quote_nonce.rand);
    // println!("rand finished");
    let mut qe_report = sgx_report_t::default();
    const RET_QUOTE_BUF_LEN : u32 = 2048;
    let mut return_quote_buf : [u8; RET_QUOTE_BUF_LEN as usize] = [0;RET_QUOTE_BUF_LEN as usize];
    let mut quote_len : u32 = 0;

    // (3) Generate the quote
    // Args:
    //       1. sigrl: ptr + len
    //       2. report: ptr 432bytes
    //       3. linkable: u32, unlinkable=0, linkable=1
    //       4. spid: sgx_spid_t ptr 16bytes
    //       5. sgx_quote_nonce_t ptr 16bytes
    //       6. p_sig_rl + sigrl size ( same to sigrl)
    //       7. [out]p_qe_report need further check
    //       8. [out]p_quote
    //       9. quote_size
    let (p_sigrl, sigrl_len) =
        if sigrl_vec.len() == 0 {
            (ptr::null(), 0)
        } else {
            (sigrl_vec.as_ptr(), sigrl_vec.len() as u32)
        };
    let p_report = (&rep.unwrap()) as * const sgx_report_t;
    let quote_type = sign_type;

    let spid : sgx_spid_t = *IAS_SPID;

    let p_spid = &spid as *const sgx_spid_t;
    let p_nonce = &quote_nonce as * const sgx_quote_nonce_t;
    let p_qe_report = &mut qe_report as *mut sgx_report_t;
    let p_quote = return_quote_buf.as_mut_ptr();
    let maxlen = RET_QUOTE_BUF_LEN;
    let p_quote_len = &mut quote_len as *mut u32;

    let result = unsafe {
        ocall_get_quote(&mut rt as *mut sgx_status_t,
                        p_sigrl,
                        sigrl_len,
                        p_report,
                        quote_type,
                        p_spid,
                        p_nonce,
                        p_qe_report,
                        p_quote,
                        maxlen,
                        p_quote_len)
    };

    if result != sgx_status_t::SGX_SUCCESS {
        return Err(result);
    }

    if rt != sgx_status_t::SGX_SUCCESS {
        println!("ocall_get_quote returned {}", rt);
        return Err(rt);
    }

    // Added 09-28-2018
    // Perform a check on qe_report to verify if the qe_report is valid
    match rsgx_verify_report(&qe_report) {
        Ok(()) => (),
        Err(x) => {
            println!("rsgx_verify_report failed with {:?}", x);
            return Err(x);
        },
    }

    // Check if the qe_report is produced on the same platform
    if ti.mr_enclave.m != qe_report.body.mr_enclave.m ||
        ti.attributes.flags != qe_report.body.attributes.flags ||
        ti.attributes.xfrm  != qe_report.body.attributes.xfrm {
        println!("qe_report does not match current target_info!");
        return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
    }

    // println!("qe_report check passed");

    // Debug
    // for i in 0..quote_len {
    //     print!("{:02X}", unsafe {*p_quote.offset(i as isize)});
    // }
    // println!("");

    // Check qe_report to defend against replay attack
    // The purpose of p_qe_report is for the ISV enclave to confirm the QUOTE
    // it received is not modified by the untrusted SW stack, and not a replay.
    // The implementation in QE is to generate a REPORT targeting the ISV
    // enclave (target info from p_report) , with the lower 32Bytes in
    // report.data = SHA256(p_nonce||p_quote). The ISV enclave can verify the
    // p_qe_report and report.data to confirm the QUOTE has not be modified and
    // is not a replay. It is optional.

    let mut rhs_vec : Vec<u8> = quote_nonce.rand.to_vec();
    rhs_vec.extend(&return_quote_buf[..quote_len as usize]);
    let rhs_hash = rsgx_sha256_slice(&rhs_vec[..]).unwrap();
    let lhs_hash = &qe_report.body.report_data.d[..32];

    // println!("rhs hash = {:02X}", rhs_hash.iter().format(""));
    // println!("report hs= {:02X}", lhs_hash.iter().format(""));

    if rhs_hash != lhs_hash {
        println!("Quote is tampered!");
        return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
    }

    let quote_vec : Vec<u8> = return_quote_buf[..quote_len as usize].to_vec();
    let (attn_report, sig, cert) = get_report_from_intel(quote_vec);
    Ok((attn_report, sig, cert))
}

type MachineId = [u8; 16];
type WorkerPublicKey = [u8; 33];

#[derive(Encode, Decode)]
struct PRuntimeInfo {
    pub version: u32,
    pub machine_id: MachineId,
    pub pubkey: WorkerPublicKey,
    pub features: Vec<u32>
}

#[derive(Encode, Decode)]
struct AttestationInfo {
    report: Vec<u8>,
    sig: Vec<u8>
}

fn generate_seal_key() -> [u8; 16] {
    let key_request = sgx_key_request_t {
        key_name: SGX_KEYSELECT_SEAL,
        key_policy: SGX_KEYPOLICY_MRSIGNER,
        isv_svn: 0_u16,
        reserved1: 0_u16,
        cpu_svn: sgx_cpu_svn_t { svn: [0_u8; 16] },
        attribute_mask: sgx_attributes_t { flags: 0, xfrm: 0 },
        key_id: sgx_key_id_t::default(),
        misc_mask: 0,
        config_svn: 0_u16,
        reserved2: [0_u8; SGX_KEY_REQUEST_RESERVED2_BYTES],
    };
    let seal_key = rsgx_get_align_key(&key_request).unwrap();

    // println!("SGX_KEYSELECT_SEAL             : {}", SGX_KEYSELECT_SEAL);
    // println!("SGX_KEYPOLICY_MRSIGNER         : {}", SGX_KEYPOLICY_MRSIGNER);
    // println!("report.body.isv_svn            : {}", report.body.isv_svn);
    // println!("report.body.config_svn         : {:?}", report.body.config_svn);
    // println!("TSEAL_DEFAULT_MISCMASK         : {}", TSEAL_DEFAULT_MISCMASK);
    // println!("seal_key.key                   : {:?}", seal_key.key);

    seal_key.key
}

#[no_mangle]
pub extern "C" fn ecall_main() -> sgx_status_t {
    let machine_id = generate_seal_key();
    println!("Generated machine id:");
    println!("{:?}", &machine_id);
    println!();

    let cpu_core_num: u32 = sgx_trts::enclave::rsgx_get_cpu_core_num();
    println!("CPU Cores:");
    println!("{:?}", cpu_core_num);
    println!();

    let ecdsa_sk = SecretKey::random(&mut rand::thread_rng());
    let ecdsa_pk = PublicKey::from_secret_key(&ecdsa_sk);
    let ecdsa_serialized_pk = ecdsa_pk.serialize_compressed();

    let runtime_info = PRuntimeInfo {
        version: 1,
        machine_id,
        pubkey: ecdsa_serialized_pk,
        features: vec![cpu_core_num, 1]
    };
    let encoded_runtime_info = runtime_info.encode();
    let hash = sp_core::hashing::blake2_512(&encoded_runtime_info);

    println!("Encoded runtime info:");
    println!("{:?}", encoded_runtime_info);

    println!("Testing RA...");

    let (attn_report_raw, sig_raw, sig_cert_raw) = create_attestation_report(&hash, sgx_quote_sign_type_t::SGX_LINKABLE_SIGNATURE).expect("error while doing remote attestation");

    let attn_report: Value = serde_json::from_str(&attn_report_raw).unwrap();
    let sig: Vec<u8> = base64::decode(&sig_raw).unwrap();
    let sig_cert_dec: Vec<u8> = base64::decode(&sig_cert_raw).unwrap();
    let sig_cert: webpki::EndEntityCert = webpki::EndEntityCert::from(&sig_cert_dec).unwrap();

    // println!("==== Loaded Attestation Report ====");
    // // println!("{}", ::serde_json::to_string_pretty(&attn_report).unwrap());
    // println!("{}", attn_report_raw);
    // println!();
    // println!("==== Loaded Report Signature ====");
    // println!("{}", sig_raw);
    // println!();
    // println!("==== Loaded Report Signing Certificate ====");
    // println!("{}", sig_cert_raw);
    // println!();

    // 2. Verify quote status (mandatory field)
    if let Value::String(quote_status) = &attn_report["isvEnclaveQuoteStatus"] {
        println!("isvEnclaveQuoteStatus = {}", quote_status);
        // match quote_status.as_ref() {
        //     "OK" => (),
        //     "GROUP_OUT_OF_DATE" | "GROUP_REVOKED" | "CONFIGURATION_NEEDED" => {
        //         // Verify platformInfoBlob for further info if status not OK
        //         if let Value::String(pib) = &attn_report["platformInfoBlob"] {
        //             let got_pib = pib::platform_info::from_str(&pib);
        //             println!("{:?}", got_pib);
        //         } else {
        //             println!("Failed to fetch platformInfoBlob from attestation report");
        //         }
        //     }
        //     _ => {
        //         println!("isvEnclaveQuoteStatus unexpected.");
        //     }
        // }
    } else {
        panic!("Failed to fetch isvEnclaveQuoteStatus from attestation report");
    }

    if let Value::String(advisory_url) = &attn_report["advisoryURL"] {
        println!("advisoryURL = {}", advisory_url);
    }

    if let Value::Array(advisory_ids) = &attn_report["advisoryIDs"] {
        if advisory_ids.len() > 0 {
            println!("advisoryIDs = {}", advisory_ids.iter().map(|id| id.to_string()).join(", "));
        }
    }

    // // 3. Verify quote body
    // if let Value::String(quote_raw) = &attn_report["isvEnclaveQuoteBody"] {
    //     let quote = base64::decode(&quote_raw).unwrap();
    //     println!("Quote = {:?}", quote);
    //     // TODO: lack security check here
    //     let sgx_quote: sgx_quote_t = unsafe{ptr::read(quote.as_ptr() as *const _)};
    //
    //     // Borrow of packed field is unsafe in future Rust releases
    //     // ATTENTION
    //     // DO SECURITY CHECK ON DEMAND
    //     // DO SECURITY CHECK ON DEMAND
    //     // DO SECURITY CHECK ON DEMAND
    //     unsafe {
    //         println!("sgx quote version = {}", sgx_quote.version);
    //         println!("sgx quote signature type = {}", sgx_quote.sign_type);
    //         println!("sgx quote report_data = {:02x}", sgx_quote.report_body.report_data.d.iter().format(""));
    //         println!("sgx quote mr_enclave = {:02x}", sgx_quote.report_body.mr_enclave.m.iter().format(""));
    //         println!("sgx quote mr_signer = {:02x}", sgx_quote.report_body.mr_signer.m.iter().format(""));
    //     }
    // } else {
    //     panic!("Failed to fetch isvEnclaveQuoteBody from attestation report");
    // }

    // let quote_status = &attn_report["isvEnclaveQuoteStatus"].as_str().unwrap_or("UNKNOWN");
    // let mut confidence_level: u8 = 128;
    // if IAS_QUOTE_STATUS_LEVEL_1.contains(quote_status) {
    //     confidence_level = 1;
    // } else if IAS_QUOTE_STATUS_LEVEL_2.contains(quote_status) {
    //     confidence_level = 2;
    // } else if IAS_QUOTE_STATUS_LEVEL_3.contains(quote_status) {
    //     confidence_level = 3;
    // } else if IAS_QUOTE_STATUS_LEVEL_5.contains(quote_status) {
    //     confidence_level = 5;
    // }

    // CL 1 means there is no known issue of the CPU
    // CL 2 means the worker's firmware up to date, and the worker has well configured to prevent known issues
    // CL 3 means the worker's firmware up to date, but needs to well configure its BIOS to prevent known issues
    // CL 5 means the worker's firmware is outdated
    // For CL 3, we don't know which vulnerable (aka SA) the worker not well configured, so we need to check the allow list
    // if confidence_level == 3 {
    //     // Filter AdvisoryIDs. `advisoryIDs` is optional
    //     if let Some(advisory_ids) = attn_report["advisoryIDs"].as_array() {
    //         for advisory_id in advisory_ids {
    //             let advisory_id = advisory_id.as_str().unwrap();
    //             if !IAS_QUOTE_ADVISORY_ID_WHITELIST.contains(&advisory_id) {
    //                 confidence_level = 4;
    //             }
    //         }
    //     }
    // }

    // if confidence_level < 128 {
    //     println!("confidenceLevel = {}", confidence_level);
    // } else {
    //     println!("Can't give a `confidenceLevel` due to don't meet minimum requirement.");
    // }

    sgx_status_t::SGX_SUCCESS
}
