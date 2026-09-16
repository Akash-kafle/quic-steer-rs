// This will contain all the LRU_HASH and any ebpf mapping i do in the codebase

// I need to make a systems list to make sure that i am keeping track of all the network that comes in and goes out 
// With source ip and anything i can find
// 

use aya_ebpf::{
    macros::{map}, maps::{RingBuf}
};

// create a ring buffer for the header normalization between v4 and v6 
#[map]
pub static RING_BUFF: RingBuf = RingBuf::with_byte_size(256 * 4096, 0);