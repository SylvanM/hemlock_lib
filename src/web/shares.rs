use rusty_crypto::{secsharing::sharing::Share256, speck};
use tokio::fs::File;

use super::{dynamo::{self, DynamoDB}, users::{bytes_to_u64, UserID}};

pub type FileID = u64;

/// Represents an entry in the shares database
#[derive(Clone)]
pub struct CiphertextShareEntry {
	pub share_owner_id: UserID,
	pub encrypted_file_owner_id: Vec<u8>,
	pub encrypted_file_id: Vec<u8>,
	pub encrypted_share: Vec<u8>,
	pub encrypted_group_key: Vec<u8>
}

/// A decrypted object containing information about an encrypted file including the share of the secret key,
/// and file ID and owner.
pub struct PlaintextShare {
	pub share_owner: UserID,
	pub file_owner: UserID,
	pub file_id: FileID,
	pub share: Share256,
	pub group_key: speck::Key
}

#[derive(Debug)]
pub enum SharesError {
	DynamoError(dynamo::DynamoError)
}

impl From<dynamo::DynamoError> for SharesError {
	fn from(value: dynamo::DynamoError) -> Self {
		Self::DynamoError(value)
	}
}

/// Converts a UserID into a byte vector by just returning the underlying binary representation,
/// in big endian.
pub fn fid_to_bytes(file_id: FileID) -> Vec<u8> {
	file_id.to_be_bytes().to_vec()
}

/// Converts a big endian byte vector into a UserID
pub fn bytes_to_fid(bytes: Vec<u8>) -> FileID {
	FileID::from_be_bytes(bytes.try_into().unwrap())
}

impl CiphertextShareEntry {

	/// Creates a share!
	pub fn new(share_owner_id: UserID, encrypted_file_owner_id: Vec<u8>, encrypted_file_id: Vec<u8>, encrypted_share: Vec<u8>, encrypted_group_key: Vec<u8>) -> CiphertextShareEntry {
		CiphertextShareEntry { share_owner_id, encrypted_file_owner_id, encrypted_file_id, encrypted_share, encrypted_group_key }
	}

	/// Decrypts this share entry into a plaintext share using the share owner's master key
	pub fn decrypt(&self, master_key: speck::Key) -> PlaintextShare {
		let decrypted_file_owner = bytes_to_u64(speck::dec_vec(master_key, self.encrypted_file_owner_id.clone()));
		let decrypted_file_id = bytes_to_fid(speck::dec_vec(master_key, self.encrypted_file_id.clone()));
		let decrypted_share: Share256 = speck::dec_vec(master_key, self.encrypted_share.clone()).try_into().unwrap();
		let decrypted_group_key = speck::dec_vec(master_key, self.encrypted_group_key.clone()).try_into().unwrap();

		PlaintextShare { 
			share_owner: self.share_owner_id, 
			file_owner: decrypted_file_owner, 
			file_id: decrypted_file_id, 
			share: decrypted_share,
			group_key: decrypted_group_key
		}
	}

}

pub async fn upload_share(db: &DynamoDB, share: CiphertextShareEntry) -> Result<(), SharesError> {
	match db.upload_share(share).await {
		Ok(_) => Ok(()),
		Err(e) => Err(e.into())
	}
}

/// Downloads a set of shares for a certain user, still encrypted.
pub async fn download_shares(db: &DynamoDB, share_owner: UserID) -> Result<Vec<CiphertextShareEntry>, SharesError> {
	let result = db.download_shares_for_user(share_owner).await?;
	Ok(result)
}