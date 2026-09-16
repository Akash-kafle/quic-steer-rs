#[derive(Debug, Clone, Copy)]
#[repr(i32)]

/**
 * i need to expand this Error ( this will be a sole error )
 * 
 * key features 
 * 
 * Singelton 
 * concurrency supported ( more than one error place for async {If need be})
 */
pub enum ParseError {
    InvalidEthernet = 1,
    UnsupportedProtocol = 2,
    Truncated = 3,
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ParseError::InvalidEthernet => write!(f, "invalid ethernet header"),
            ParseError::UnsupportedProtocol => write!(f, "unsupported protocol"),
            ParseError::Truncated => write!(f, "truncated packet"),
        }
    }
}

#[derive(Debug)]
pub enum DriverError {
    Timeout,
    Overrun,
}