//!
//! Code that deals with uploading and downloading files from the hemlock servers
//! 

use std::{fs::File, io::{Read, Write}, path::PathBuf, thread::spawn};

use aws_sdk_s3::{error::SdkError, operation::get_object::GetObjectError, Client};
use aws_smithy_runtime_api::http::Response;
use rusty_crypto::{lettuce::Plaintext, speck};

use super::{shares::FileID, users::UserID};

/// A hex string of a 128 bit number, the first 64 bits of which are the user id of the 
/// owner of the file, the second 64 bits are the file id of the file.
pub type FileKey = String;

/// The bucket name for the files database
const HL_FILES_BUCKET: &str = "hemlockfiles";

/// A file related error
#[derive(Debug)]
pub enum FileError {
	GetObjectError(SdkError<GetObjectError, Response>),
	StdIOError(std::io::Error)
}

impl From<aws_smithy_runtime_api::client::result::SdkError<GetObjectError, aws_smithy_runtime_api::http::Response>> for FileError {
    fn from(value: aws_smithy_runtime_api::client::result::SdkError<GetObjectError, aws_smithy_runtime_api::http::Response>) -> Self {
        Self::GetObjectError(value)
    }
}

impl From<std::io::Error> for FileError {
	fn from(value: std::io::Error) -> Self {
		Self::StdIOError(value)
	}
}

fn make_file_key(user_id: UserID, file_id: FileID) -> FileKey {
	format!("{:016X}{:16X}", user_id, file_id)
}

fn parse_file_key(file_key: FileKey) -> (UserID, FileID) {
	let user_id_str = &file_key[0..32];
	let file_id_str = &file_key[32..64];

	(
		UserID::from_str_radix(user_id_str, 16).unwrap(), 
		UserID::from_str_radix(file_id_str, 16).unwrap()
	)
}

// MARK: Methods

/// Returns an S3 client
pub async fn make_client() -> Client {
	let config = aws_config::load_from_env().await;
	aws_sdk_s3::Client::new(&config)
}

/// Downloads a file identified by its user owner ID and file ID, and decrypts the object, writing it to a 
/// given file.
pub async fn retrieve_file(client: &Client, user_id: UserID, file_id: FileID, secret_key: speck::Key, file: &mut File) -> Result<(), FileError> {

	let mut object = client
		.get_object()
		.bucket(HL_FILES_BUCKET)
		.key(make_file_key(user_id, file_id))
		.send()
		.await?;

	let mut ciphertext_buffer = Vec::<u8>::new();

	while let Some(bytes) = object.body.try_next().await.unwrap() {
		// these bytes need to be decrypted!
		for byte in bytes {
			ciphertext_buffer.push(byte)
			// yeah yeah, this is slow. I know!
		}
	}

	let plaintext_buffer = speck::dec_vec(secret_key, ciphertext_buffer);
	file.write_all(&plaintext_buffer)?;

	Ok(())

}

pub async fn encrypt_and_upload(client: &Client, user_id: UserID, file_id: FileID, secret_key: speck::Key, file: &mut File) -> Result<(), FileError> {
	let size = file.metadata().unwrap().len();
	let mut bytes = vec![0 ; size as usize];

	file.read(&mut bytes)?;

	let ciphertext = speck::enc_vec(secret_key, bytes);

	let _ = client 
		.put_object()
		.bucket(HL_FILES_BUCKET)
		.key(make_file_key(user_id, file_id))
		.body(ciphertext.into())
		.send()
		.await;

	Ok(())
}