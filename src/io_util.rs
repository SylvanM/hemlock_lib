//! A collection of utilities just for the interface of the program

/// The error code type
pub type Error = i32;

// MARK: Error Codes

#[no_mangle]
pub static SUCCESS: Error = 0;
#[no_mangle]
pub static INVALID_LAUNCH_MODE: Error = 1;
#[no_mangle]
pub static EMAIL_TAKEN: Error		 = 2;
#[no_mangle]
pub static CONNECTION_ERROR: Error	 = 3;
#[no_mangle]
pub static DATA_ERROR: Error 		 = 4;
#[no_mangle]
pub static USER_DOES_NOT_EXIST: Error = 5;
#[no_mangle]
pub static EMAIL_DOES_NOT_EXIST: Error = 6;
