use core::any::Any;

use learning_common::{NormalizedPacket};
use crate::utils::error::ParseError;
use network_types::{
    eth::EthHdr, icmp::{Icmpv6Hdr, Icmpv4Hdr}};

use crate::utils::parser::ptr_at;


/**
 * I am trying to create a rule book for what i am trying to make the network stack do
 */
pub struct ParseRule;

impl ParseRule{

    pub fn parse_icmpv4(icmpv4: * const Icmpv4Hdr)-> IcmpDecision{
        let type_  = unsafe {
            (*icmpv4).type_
        };
        let code = unsafe {
            (*icmpv4).code
        };
        return Self::classify_icmpv4(type_, code);
    }

    pub fn parse_icmpv6(icmpv6: * const Icmpv6Hdr)-> IcmpDecision{
        let type_  = unsafe {
            (*icmpv6).type_
        };
        return Self::classify_icmpv6(type_);
    }

    
/**
 *  * 
 * IPv4 (per opsec draft reasoning)

Type	Code	    Decision	    Why
0    (Echo Reply) -	Allow	    Diagnostic, low risk
3 (Dest Unreachable) 4 (Frag Needed)	Allow, never drop	Path MTU discovery depends on it; dropping causes silent connection hangs
3 (Dest Unreachable)	other codes	Allow	Diagnostic
5 (Redirect)	any	Deny	Real MITM/route-hijack vector, no legitimate host-facing use
8 (Echo Request)	—	Rate-limit	Legitimate but floodable
11 (Time Exceeded)	—	Allow	traceroute depends on it; not commonly weaponized
everything else	—	Deny (default)	No standard operational need

 */
pub fn classify_icmpv4(type_: u8, code: u8) -> IcmpDecision {
    match (type_, code) {
        (3, 4) => IcmpDecision::Allow,      // Dest Unreachable, Frag Needed — PMTUD
        (0 | 3 | 11, _) => IcmpDecision::Allow,      // Dest Unreachable, other codes
        (8, _) => IcmpDecision::RateLimit(),  // Echo Request
        (5, _) | _ => IcmpDecision::Deny,       // Redirect
    }
}
/**
 * IPv6 (per RFC 4890, host/transit firewall guidance)

Type	Decision	Why
1 (Dest Unreachable)	Allow	Diagnostic
2 (Packet Too Big)	Allow, never drop	PMTUD equivalent for v6; same failure mode as v4 frag-needed
3 (Time Exceeded)	Allow	traceroute
128/129 (Echo Request/Reply)	Rate-limit	Same reasoning as v4
133–137 (Neighbor Discovery)	Allow, scope-checked	Required for basic v6 operation, not optional diagnostics
everything else	Deny (default)	No standard operational need
 */

pub fn classify_icmpv6(type_: u8) -> IcmpDecision{

       match type_ {
        1 | 2 | 3 => IcmpDecision::Allow,
        
        // Types 128 & 129: Echo Request and Echo Reply
        128 | 129 => IcmpDecision::RateLimit(),
        
        // Types 133 to 137: Neighbor Discovery (inclusive range syntax)
        133..=137 => IcmpDecision::Allow,
        
        // Everything else: Deny by default
        _ => IcmpDecision::Deny,
    }
    
}
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpDecision {
        Allow,
        Deny,
    }

impl IcmpDecision{

    pub fn RateLimit()-> IcmpDecision{
        return IcmpDecision::Allow;
    }


}

