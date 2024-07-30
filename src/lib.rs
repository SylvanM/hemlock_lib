

use std::ffi::c_int;

use io_util::*;
use rusty_crypto::sha512;

mod web;
mod splitting;
mod io_util;

// MARK: Public Interface

pub fn hash_bytes(plaintext: Vec<u8>, digest: &mut sha512::Digest) -> Error {
    *digest = sha512::hash(plaintext.to_vec());
    SUCCESS
}

pub fn hash_str(plaintext: String, digest: &mut sha512::Digest) -> Error {
    let bytes = plaintext.as_bytes().to_vec();
    hash_bytes(bytes, digest)
}

// MARK: C Utility

/// Converts a C pointer into a rust Vector
fn c_ptr_to_vec<T: Copy>(ptr: *mut T, len: c_int) -> Vec<T> {
    unsafe {
        // this is a REALLY silly thing to do, but I don't know a workaround.
        let mut vec = Vec::new();
        for i in 0..len {
            vec.push(*ptr.add(i as usize));
        }
        vec
    }
}

/// Writes the contents of a rust byte vector to a C pointer, and returns
/// the pointer to the C array
fn write_vec_to_c_ptr(vec: Vec<u8>) -> *mut u8 {

    use std::alloc::*;

    let layout = match Layout::array::<u8>(vec.len()) {
        Ok(l) => l,
        Err(e) => panic!("Error allocating array: {:?}", e),
    };

    let ptr = unsafe {
        alloc(layout)
    };
    
    for i in 0..vec.len() {
        unsafe {
            *(ptr.add(i)) = vec[i];
        }
    }

    ptr
}

// MARK: C Interface
pub mod c_api {

    use rusty_crypto::{lettuce, sha512, speck};
    use tokio::runtime::Runtime;
    use std::ffi::{self, *};

    use crate::{c_ptr_to_vec, io_util::*, splitting, web::{dynamo::DynamoDB, users::{self, UserID, UsersError}}, write_vec_to_c_ptr};

    // MARK: Constants to publish

    #[no_mangle]
    pub static ENCRYPTED_SECRET_KEY_LEN: usize = splitting::ENCRYPTED_SECRET_KEY_LEN;
    #[no_mangle]
    pub static PUBLIC_KEY_LEN: usize = lettuce::PK_BYTES;
    #[no_mangle]
    pub static SECRET_KEY_LEN: usize = lettuce::SK_BYTES;
    #[no_mangle]
    pub static SPECK_KEY_LEN: usize = speck::KEY_SIZE;
    #[no_mangle]
    pub static SHA512_DIGEST_LEN: usize = sha512::DIGEST_BYTE_COUNT;

    // MARK: Crypto

    #[no_mangle]
    pub extern "C" fn capi_hash_bytes(pt: *mut u8, pt_len: c_int, digest: &mut sha512::Digest) -> c_int {
        let as_vector = c_ptr_to_vec(pt, pt_len);
        crate::hash_bytes(as_vector, digest)
    }

    #[no_mangle]
    pub extern "C" fn capi_hash_str(pt: *const c_char, digest: &mut sha512::Digest) -> c_int {
        let cstr = unsafe { CStr::from_ptr(pt) };
        let string = String::from_utf8_lossy(cstr.to_bytes()).to_string();
        crate::hash_str(string.to_string(), digest)
    }

    #[no_mangle]
    pub extern "C" fn capi_enc(pt: *mut u8, pt_len: c_int, key: &speck::Key, ct_len: &mut c_int) -> *mut u8 {
        let bytes = c_ptr_to_vec(pt, pt_len);
        let ciphertext_bytes = speck::enc_vec(*key, bytes);
        *ct_len = ciphertext_bytes.len() as c_int;
        write_vec_to_c_ptr(ciphertext_bytes)
    }

    #[no_mangle]
    pub extern "C" fn capi_dec(ct: *mut u8, ct_len: c_int, key: &speck::Key, pt_len: &mut c_int) -> *mut u8 {
        let bytes = c_ptr_to_vec(ct, ct_len);
        let plaintext_bytes = speck::dec_vec(*key, bytes);
        *pt_len = plaintext_bytes.len() as c_int;
        write_vec_to_c_ptr(plaintext_bytes)
    }

    // MARK: Asynchronicity

    /// Creates a Rust runtime object and allocates it on the heap, then returns a pointer to that object!
    #[no_mangle]
    pub extern "C" fn capi_create_runtime() -> *mut Runtime {
        match Runtime::new() {
            Ok(rt) => Box::into_raw(Box::new(rt)),
            Err(e) => panic!("Error creating tokio runtime: {:?}", e)
        }
    }

    #[no_mangle]
    pub extern "C" fn capi_test_async(rt: *mut Runtime, callback: extern fn(c_int) -> ()) -> c_int {
        unsafe {
            if rt.is_null() {
                return -1; // Indicate error
            }
            let rt = &*rt;

            rt.spawn(async move {
                println!("This code is asynchronous!");
                callback(0);
            });

            0 // Indicate success
        }
    }

    #[no_mangle]
    pub extern "C" fn capi_destroy_runtime(rt: *mut Runtime) {
        if rt.is_null() {
            return;
        }
        unsafe {
            drop(Box::from_raw(rt))
        }
    }
    
    // MARK: Users

    /// A user of Hemlock, in a C-representable struct
    #[repr(C)]
    pub struct CUser<'a> {
        user_id: u64,
        email: &'a CStr,
        public_key: lettuce::PublicKey,
        encrypted_secret_key: *const u8,
        master_key_hash: sha512::Digest
    }

    // Creates a user with a given email address. This is an asynchronous function that calls a callback when finished.
    // The callback is passed the error code (0 if success), the user ID (0 if failed), and the master key (all 0's if failed).
    #[no_mangle]
    pub extern "C" fn capi_create_user(rt: *mut Runtime, email_ptr: *const c_char, callback: extern fn(c_int, c_ulonglong, &mut speck::Key)) {
        
        println!("C function entered");

        let rt = unsafe { &*rt };
        
        let db = rt.block_on(DynamoDB::new());

        println!("Database abstraction created");

        let cstr = unsafe { CStr::from_ptr(email_ptr) };
        
        rt.spawn(async move {
            let email_str = String::from_utf8_lossy(cstr.to_bytes()).to_string();

            println!("About to make user creation web call");
            let result = users::create_user(&db, email_str).await;
            println!("DONE with that!");
            
            match result {
                Ok((uid, mut mk)) => callback(SUCCESS, uid, &mut mk),
                Err(UsersError::EmailTaken(_)) => callback(EMAIL_TAKEN, 0, &mut [0 ; 32]),
                Err(e) => {
                    println!("Encountered error: {:?}", e);
                    callback(CONNECTION_ERROR, 0, &mut [0 ; 32])
                }
            }
        });
    }

    #[no_mangle]
    pub extern "C" fn capi_download_user(rt: *mut Runtime, user_id: UserID, callback: extern fn(c_int, *mut CUser)) {
        // TODO: Add callback to this function header, and maybe also create a struct to pass into it!
        // Make a rust struct that represents a User, and make it compatible with C, then pass that! that would be cool

        let rt = unsafe { &*rt };
        let db = rt.block_on(DynamoDB::new());

        rt.spawn(async move {
            match users::get_user(&db, user_id).await {
                Ok(mut user_entry) => {
                    let c_string = CString::new(user_entry.email.as_str()).unwrap();
                    let cstr = c_string.as_c_str();

                    let mut c_user = CUser {
                        user_id,
                        email: cstr,
                        public_key: user_entry.public_key,
                        encrypted_secret_key: user_entry.encrypted_secret_key.as_mut_ptr(),
                        master_key_hash: user_entry.master_key_hash.try_into().unwrap(),
                    };
                    
                    callback(SUCCESS, &mut c_user);
                },
                Err(UsersError::UserDoesNotExist) => callback(USER_DOES_NOT_EXIST, core::ptr::null_mut()),
                Err(_) => callback(CONNECTION_ERROR, core::ptr::null_mut())
            }
        });
    }

}

// MARK: Tests

#[cfg(test)]
mod tests {
    use std::fs::File;

    use crate::*;

    use web::{dynamo, messages::{self}, shares, users::{self, UserID, UsersError}};
    use rusty_crypto::{secsharing::sharing::{Share256, SHARE_SIZE_BYTES}, sha512, speck};


    const SYLVAN_USER_ID: UserID = 15893677956707774784;
    const SYLVAN_MASTER_KEY: users::MasterKey = [
        0xBB, 0xF2, 0xA7, 0x58, 0xAD, 0x34, 0x9B, 0x95, 
        0x38, 0xCD, 0x3E, 0x26, 0xF2, 0x6C, 0x92, 0xD7, 
        0x6B, 0xE4, 0xDD, 0xC1, 0x5C, 0x69, 0x56, 0x4F, 
        0x8C, 0x9B, 0x4D, 0xEA, 0x08, 0xFF, 0x8C, 0x93
    ];

    const ALEPH_USER_ID: UserID = 14338123416841738431;
    const ALEPH_MASTER_KEY: users::MasterKey = [
        0x58, 0x19, 0x31, 0x92, 0x05, 0x7E, 0x77, 0xB8, 
        0x4C, 0xA7, 0xC1, 0x40, 0x51, 0xC0, 0x64, 0x00, 
        0x15, 0x1C, 0x13, 0x25, 0xFE, 0x52, 0xAA, 0x3D, 
        0xE4, 0x31, 0x84, 0x69, 0xF8, 0x66, 0x29, 0x4B
    ];

    const JOE_USER_ID: UserID = 2181071344201131471;
    const JOE_MASTER_KEY: users::MasterKey = [
        0x31, 0xF1, 0x07, 0x98, 0xD8, 0xB5, 0x72, 0x52, 
        0x39, 0x2E, 0xFC, 0x30, 0x84, 0x3A, 0xD3, 0xA2, 
        0xF3, 0x98, 0x1F, 0xCC, 0x64, 0xD9, 0x6F, 0xC5, 
        0xDC, 0x83, 0x32, 0xA5, 0x3C, 0xEB, 0xAF, 0xF6
    ];

    #[tokio::test]
    async fn key_enc_test() {
        let key = speck::gen();
        let keykey = speck::gen();

        let encrypted_key = speck::enc_vec(key, keykey.to_vec());

        println!("{}", encrypted_key.len())
    }


    #[tokio::test]
    async fn user_creation_test() {
        // let email = "sylvan.martin@gmail.com";
        // let email = "alephnulltim@gmail.com";
        let email = "joe@joe.joe";

        let dynamo_interfacce = dynamo::DynamoDB::new().await;

        let master_key = users::create_user(&dynamo_interfacce, email.to_string()).await;

        match master_key {
            Ok((_, k)) => {
                println!("Successfully generated master key:");
                print!("[\n");
                for i in 0..speck::KEY_SIZE {
                    if i % 8 == 0 {
                        print!("\t");
                    }
                    print!("0x{:02X}", k[i]);
                    if i != speck::KEY_SIZE - 1 {
                        print!(", ");
                    }
                    if i % 8 == 7 {
                        print!("\n");
                    }
                }
                print!("]");
            },
            Err(UsersError::EmailTaken(s)) => println!("Email \"{}\" is taken.", s),
            Err(e) => panic!("Error: {:?}", e)
        };
    }

    #[tokio::test]
    async fn test_downloading_user() {
        let db = dynamo::DynamoDB::new().await;

        let email = "sylvan.martin@gmail.com";

        match users::get_user_for_email(&db, email.to_string()).await {
            Ok(u) => {
                let mk_hash = u.master_key_hash;
                let correct_hash = sha512::hash(SYLVAN_MASTER_KEY.into()).to_vec();

                assert_eq!(mk_hash, correct_hash);
            },
            Err(e) => panic!("Error: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_messaging() {
        let db = dynamo::DynamoDB::new().await;

        // we are going to split this secret between aleph and joe. The file ID will just be 0.
        let secret = speck::gen();
        let shares = rusty_crypto::secsharing::sharing::distribute(2, 2, secret);
    
        match messages::send_message(&db, JOE_USER_ID, SYLVAN_USER_ID, 0, shares[0], speck::gen()).await {
            Ok(_) => (),
            Err(e) => panic!("Error: {:?}", e),
        };

        match messages::send_message(&db, ALEPH_USER_ID, SYLVAN_USER_ID, 0, shares[1], speck::gen()).await {
            Ok(_) => (),
            Err(e) => panic!("Error: {:?}", e),
        };

        // aleph and joe will pull their messages and see what happens!
        match messages::process_inbox(&db, ALEPH_USER_ID, ALEPH_MASTER_KEY).await {
            Ok(_) => (),
            Err(e) => panic!("Error: {:?}", e)
        };

        match messages::process_inbox(&db, JOE_USER_ID, JOE_MASTER_KEY).await {
            Ok(_) => (),
            Err(e) => panic!("Error: {:?}", e)
        };

        // now, let's download the shares, and actually try to combine them!
        let aleph_shares_enc = match shares::download_shares(&db, ALEPH_USER_ID).await {
            Ok(s) => s,
            Err(e) => panic!("{:?}", e)
        };

        let joe_shares_enc = match shares::download_shares(&db, JOE_USER_ID).await {
            Ok(s) => s,
            Err(e) => panic!("{:?}", e)
        };

        let aleph_shares: Vec<shares::PlaintextShare> = aleph_shares_enc.into_iter().map(|s| s.decrypt(ALEPH_MASTER_KEY)).collect();
        let joe_shares: Vec<shares::PlaintextShare> = joe_shares_enc.into_iter().map(|s| s.decrypt(JOE_MASTER_KEY)).collect();

        // Now, we search for a share for file ID 0 and from Sylvan
        let mut aleph_share: Share256 = [1 ; SHARE_SIZE_BYTES];
        for share in aleph_shares {
            if share.file_id == 0 && share.file_owner == SYLVAN_USER_ID {
                aleph_share = share.share;
                break;
            }
        }

        let mut joe_share: Share256 = [1 ; SHARE_SIZE_BYTES];
        for share in joe_shares {
            if share.file_id == 0 && share.file_owner == SYLVAN_USER_ID {
                joe_share = share.share;
                break;
            }
        }

        // make sure we actually got them correct!

        let reconstructed_secret = rusty_crypto::secsharing::sharing::reconstruct(2, vec![joe_share, aleph_share]);
        assert_eq!(reconstructed_secret, secret);

    }

    #[tokio::test]
    async fn test_sylvan_split() {
        // we are going to have a file, sylvans_secret, and have sylvan split the file and send it to aleph and joe.

        let db = dynamo::DynamoDB::new().await;

        let mut sylvans_secret = File::open("test_files/sylvans_secret.pdf").unwrap();

        match splitting::split_and_share(&mut sylvans_secret, SYLVAN_USER_ID, 2, vec![ALEPH_USER_ID, JOE_USER_ID]).await {
            Ok(_) => println!("Successfully split file"),
            Err(e) => panic!("Error splitting file: {:?}", e)
        }

        // go ahead and have aleph and joe refresh their inbox.
        let _ = messages::process_inbox(&db, ALEPH_USER_ID, ALEPH_MASTER_KEY).await;
        let _ = messages::process_inbox(&db, JOE_USER_ID, JOE_MASTER_KEY).await;

    }

    #[tokio::test]
    async fn test_publish() {
        let db = dynamo::DynamoDB::new().await;

        // let aleph and joe publish their shares
        let aleph_share = match shares::download_shares(&db, ALEPH_USER_ID).await {
            Ok(s) => s[0].decrypt(ALEPH_MASTER_KEY),
            Err(e) => panic!("Error downloading shares: {:?}", e)
        };

        let joe_share = match shares::download_shares(&db, JOE_USER_ID).await {
            Ok(s) => s[0].decrypt(JOE_MASTER_KEY),
            Err(e) => panic!("Error downloading shares: {:?}", e)
        };

        debug_assert_eq!(aleph_share.file_id, joe_share.file_id);

        println!("File ID is {}", aleph_share.file_id);
            
        match splitting::publish_share(aleph_share.file_id, aleph_share.file_owner, aleph_share.share, aleph_share.group_key).await {
            Ok(_) => println!("Aleph published his share!"),
            Err(e) => panic!("Error publishing Aleph's share: {:?}", e)
        };

        match splitting::publish_share(joe_share.file_id, joe_share.file_owner, joe_share.share, joe_share.group_key).await {
            Ok(_) => println!("Joe published his share!"),
            Err(e) => panic!("Error publishing Joe's share: {:?}", e)
        };

    }

    #[tokio::test]
    async fn test_aleph_recover() {
        // either guy should be able to recover the share!
        let mut aleph_file = File::create("test_files/alephs_recovery.pdf").unwrap();

        let db = dynamo::DynamoDB::new().await;

        // go ahead and download the (one) share
        let share_entry = shares::download_shares(&db, ALEPH_USER_ID).await.unwrap()[0].decrypt(ALEPH_MASTER_KEY);

        match splitting::recover_file(share_entry.file_id, SYLVAN_USER_ID, share_entry.group_key, &mut aleph_file).await {
            Ok(_) => println!("Recovered the file!"),
            Err(e) => panic!("Error recovering file: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_joe_recover() {
        // either guy should be able to recover the share!
        let mut joe_file = File::create("test_files/joes_recovery.pdf").unwrap();

        let db = dynamo::DynamoDB::new().await;

        // go ahead and download the (one) share
        let share_entry = shares::download_shares(&db, JOE_USER_ID).await.unwrap()[0].decrypt(JOE_MASTER_KEY);

        match splitting::recover_file(share_entry.file_id, SYLVAN_USER_ID, share_entry.group_key, &mut joe_file).await {
            Ok(_) => println!("Recovered the file!"),
            Err(e) => panic!("Error recovering file: {:?}", e),
        }
    }
}