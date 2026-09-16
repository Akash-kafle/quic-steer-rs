use core::error;
use core::mem;


use aya_ebpf::{
    bindings::xdp_action, macros::{map,xdp}, maps::{RingBuf, xdp}, programs::XdpContext,
};
use learning_common::NormalizedPacket;

use crate::utils::error::ParseError;
pub struct RequestData{
    source: u8,
    dst: u8,
    checksum: u16,
    data: u32     
}


impl From<NormalizedPacket> for RequestData{
    fn from(N: NormalizedPacket)->Self{
        RequestData::default
    }

}

impl RequestData {
    const default: RequestData =  RequestData{
        source: 0, dst : 0 , checksum: 0 , data:0
    };
    
}

pub fn Structure_TCP()-> RequestData{

    return RequestData::default;

}

pub fn Structure_UDP()-> RequestData{
    return RequestData::default;

}

pub fn check_access(
    RequestData { source, dst, checksum, data }: RequestData
)-> bool{

    return true;
}


pub fn ipv4_to_16(src: [u8;4]) -> [u8;16] {
    let mut out = [0u8;16];
    // zero-prefix: [0..12] = 0, last 4 bytes IPv4
    out[12..16].copy_from_slice(&src);
    out
}

pub fn ipv4_to_16_zeroed(src: [u8;4]) -> [u8;16] {
    let mut out = [0u8;16];
    out[12..16].copy_from_slice(&src);
    out
}

pub fn ipv4_to_16_mapped(src: [u8;4]) -> [u8;16] {
    let mut out = [0u8;16];
    out[10] = 0xff;
    out[11] = 0xff;
    out[12..16].copy_from_slice(&src);
    out
}

pub fn ipv16_to_ipv4(ip16: [u8;16]) -> Option<[u8;4]> {
    // Accept either zero-prefix or IPv4-mapped ::ffff
    if ip16[0..12] == [0u8;12] {
        let mut v = [0u8;4];
        v.copy_from_slice(&ip16[12..16]);
        Some(v)
    } else if ip16[0..10] == [0u8;10] && ip16[10..12] == [0xff, 0xff] {
        let mut v = [0u8;4];
        v.copy_from_slice(&ip16[12..16]);
        Some(v)
    } else {
        None
    }
}

pub fn pair_to_32(src16: [u8;16], dst16: [u8;16]) -> [u8;32] {
    let mut out = [0u8;32];
    out[0..16].copy_from_slice(&src16);
    out[16..32].copy_from_slice(&dst16);
    out
}

pub fn split_32(pair: [u8;32]) -> ([u8;16],[u8;16]) {
    let mut a = [0u8;16];
    let mut b = [0u8;16];
    a.copy_from_slice(&pair[0..16]);
    b.copy_from_slice(&pair[16..32]);
    (a,b)
}

pub fn ipv4_pair_to_32(src4: [u8;4], dst4: [u8;4]) -> [u8;32] {
    pair_to_32(ipv4_to_16_zeroed(src4), ipv4_to_16_zeroed(dst4))
}

#[inline(always)]
pub fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ParseError> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(ParseError::InvalidEthernet);
    }

    Ok((start + offset) as *const T)
}