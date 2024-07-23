//! A collection of utilities just for the interface of the program

/// The error code type
pub type Error = i32;

// MARK: Error Codes

pub const SUCCESS: Error = 0;

pub const INVALID_LAUNCH_MODE: Error = 1;
pub const EMAIL_TAKEN: Error		 = 2;
pub const CONNECTION_ERROR: Error	 = 3;
pub const DATA_ERROR: Error 		 = 4;
