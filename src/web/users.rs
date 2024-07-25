use std::collections::HashMap;

use aws_sdk_dynamodb::types::AttributeValue;
use rand::Rng;
use rusty_crypto::{lettuce, sha512, speck};

use super::dynamo::{self, DynamoDB, TableKeyValues};

/// A user's Master Key, which is a Speck key.
pub type MasterKey = speck::Key;

/// A user ID
pub type UserID = u64;

/// An entry in the users table
pub struct UserEntry {
	pub user_id: UserID,
	pub email: String,
	pub public_key: lettuce::PublicKey,
	pub encrypted_secret_key: Vec<u8>,
	pub master_key_hash: Vec<u8>
}

impl UserEntry {

	/// Creates a UserEntry from the data it would contain!
	pub fn new(user_id: UserID, email: String, public_key: lettuce::PublicKey, encrypted_secret_key: Vec<u8>, master_key_hash: Vec<u8>) -> UserEntry {
		UserEntry { user_id, email, public_key, encrypted_secret_key, master_key_hash }
	}

}

#[derive(Debug)]
pub enum UsersError {
	UserDoesNotExist,
	DynamoError(dynamo::DynamoError),
	EmailDoesNotExist(String),
	EmailTaken(String)
}

impl From<dynamo::DynamoError> for UsersError {
	fn from(value: dynamo::DynamoError) -> Self {
		UsersError::DynamoError(value)
	}
}

/// Converts a u64 into a byte vector by just returning the underlying binary representation,
/// in big endian.
pub fn u64_to_bytes(user_id: UserID) -> Vec<u8> {
	user_id.to_be_bytes().to_vec()
}

/// Converts a big endian byte vector into a u64
pub fn bytes_to_u64(bytes: Vec<u8>) -> u64 {
	u64::from_be_bytes(bytes.try_into().unwrap())
}

pub async fn create_user(db: &DynamoDB, email: String) -> Result<(UserID, MasterKey), UsersError> {
	match db.email_exists(email.clone()).await {
		Ok(true) => Err(UsersError::EmailTaken(email)),
		Err(e) => Err(UsersError::DynamoError(e)),
		Ok(false) => {
			// this email is free, so we can use it!

			let mut user_id: UserID;

			// generate a unique user_id!
			loop {
				user_id = rand::thread_rng().gen();
				if !db.user_id_exists(user_id).await? { break; }
			}

			let master_key = speck::gen();
			let keypair = lettuce::gen();

			let encrypted_secret_key = speck::enc_vec(master_key, keypair.secret_key.to_vec());
			let master_key_hash = sha512::hash(master_key.to_vec());

			match db.upload_user_info(
				user_id, 
				email, 
				keypair.public_key, 
				encrypted_secret_key, 
				master_key_hash.to_vec()
			).await {
				Ok(_) => (),
				Err(e) => return Err(UsersError::DynamoError(e)),
			}

			Ok((user_id, master_key))
		}
	}
}

pub async fn get_user_for_email(db: &DynamoDB, email: String) -> Result<UserEntry, UsersError> {
	match db.email_exists(email.clone()).await {
		Ok(false) => Err(UsersError::EmailDoesNotExist(email)),
		Err(e) => Err(UsersError::DynamoError(e)),
		Ok(true) => Ok(db.download_user_for_email(email).await?)
	}
}

pub async fn get_pubkey(db: &DynamoDB, user_id: UserID) -> Result<lettuce::PublicKey, UsersError> {
	match db.user_id_exists(user_id).await {
		Ok(false) => Err(UsersError::UserDoesNotExist),
		Err(e) => Err(UsersError::DynamoError(e)),
		Ok(true) => match db.download_user_entry(user_id).await {
			Ok(user) => Ok(user.public_key),
			Err(e) => Err(UsersError::DynamoError(e))
		}
	}
}

pub async fn get_encrypted_secretkey(db: &DynamoDB, user_id: UserID) -> Result<Vec<u8>, UsersError> {
	match db.download_user_entry(user_id).await {
		Ok(u) => Ok(u.encrypted_secret_key),
		Err(e) => Err(UsersError::DynamoError(e))
	}
}

pub async fn get_user(db: &DynamoDB, user_id: UserID) -> Result<UserEntry, UsersError> {
	Ok(db.download_user_entry(user_id).await?)
}