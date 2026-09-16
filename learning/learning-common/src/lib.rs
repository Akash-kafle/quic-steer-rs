#![no_std]

use aya_ebpf::{
    macros::{map}, maps::{RingBuf, HashMap, Array}
};

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct NormalizedPacket {
    // Normalize both IPv4 and IPv6 into a uniform 16-byte array
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,    // e.g., 17 for UDP/QUic
    pub payload_len: u32,
}

impl NormalizedPacket {
    pub const DEFAULT: NormalizedPacket = NormalizedPacket {
        src_ip: 0,
        dst_ip: 0,
        src_port: 0,
        dst_port: 0,
        protocol: 0,
        payload_len: 0,
    };
}

impl Default for NormalizedPacket {
    fn default() -> Self {
        Self::DEFAULT
    }
}

pub const COUNTER_PASS: u32 = 0;
pub const COUNTER_DROP: u32 = 1;

#[map]
pub static COUNTERS: Array<u64> = Array::with_max_entries(2, 0);

#[map]
pub static IPV6_TO_ID: HashMap<[u8;16], u32> = HashMap::with_max_entries(1024, 0);

#[map]
pub static NEXT_ID: Array<u32> = Array::with_max_entries(1, 0);

#[map]
pub static IP_BY_ID: HashMap<u32, [u8;16]> = HashMap::with_max_entries(1024, 0);

pub fn get_or_assign_id(ip: [u8;16]) -> u32 {
    unsafe {
        if let Some(id) = IPV6_TO_ID.get(&ip) {
            return *id;
        }
        let next = match NEXT_ID.get(0) {
            Some(v) => *v,
            None => 1u32,
        };
        let id = next;
        let _ = IPV6_TO_ID.insert(&ip, &id, 0);
        let _ = IP_BY_ID.insert(&id, &ip, 0);
        let new_next = next.wrapping_add(1);
        let _ = NEXT_ID.set(0, new_next, 0);
        id
    }
}

pub fn ip_from_id(id: u32) -> Option<[u8;16]> {
    unsafe { IP_BY_ID.get(&id).map(|v| *v) }
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for NormalizedPacket {}


