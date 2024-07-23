use std::fs::File;

use rand::Rng;
use rusty_crypto::{secsharing::sharing::{Share256, SHARE_SIZE_BYTES}, speck::{self, Key}};

use super::{dynamo::*, shares::FileID, users::{bytes_to_u64, u64_to_bytes, UserID}};

#[derive(PartialEq, Debug)]
pub struct PlaintextShareStatusEntry {
	pub owner_id: UserID,
	pub file_id: FileID,
	pub published_shares: Vec<Share256>,
	pub threshold: usize
}

#[derive(PartialEq, Debug)]
pub struct CiphertextShareStatusEntry {
	pub file_owner: UserID,
	pub file_id: FileID, 
	pub encrypted_published_shares: Vec<u8>,
	pub encrypted_threshold: Vec<u8>
}

impl CiphertextShareStatusEntry {

	fn decrypt(&self, key: speck::Key) -> PlaintextShareStatusEntry {

		let plaintext_list = speck::dec_vec(key, self.encrypted_published_shares.clone());
		
		// now, we split this into shares!
		let share_count = plaintext_list.len() / SHARE_SIZE_BYTES;
		let mut published_shares = vec![[0 ; SHARE_SIZE_BYTES] ; share_count];

		for i in 0..share_count {
			published_shares[i] = plaintext_list[(i * SHARE_SIZE_BYTES)..((i + 1) * SHARE_SIZE_BYTES)].try_into().unwrap();
		}

		PlaintextShareStatusEntry { 
			owner_id: self.file_owner, 
			file_id: self.file_id, 
			published_shares,
			threshold: bytes_to_u64(speck::dec_vec(key, self.encrypted_threshold.clone())) as usize
		}
	}

}

impl PlaintextShareStatusEntry {

	fn encrypt(&self, key: speck::Key) -> CiphertextShareStatusEntry {

		let vec_list: Vec<Vec<u8>> = self.published_shares.iter().map(|s| s.to_vec()).collect();
		let plaintext_list = vec_list.concat();
		let encrypted_list = speck::enc_vec(key, plaintext_list);

		CiphertextShareStatusEntry {
			file_owner: self.owner_id,
			file_id: self.file_id,
			encrypted_published_shares: encrypted_list,
			encrypted_threshold: speck::enc_vec(key, u64_to_bytes(self.threshold as u64))
		}

	}

}

#[test]
fn test_encryption_symmetry() {

	for _ in 0..100 {
		let mut pub_shares = vec![[0u8 ; SHARE_SIZE_BYTES] ; rand::thread_rng().gen_range(10..100)];

		for i in 0..pub_shares.len() {
			let mut share = [0u8 ; SHARE_SIZE_BYTES];
			for i in 0..SHARE_SIZE_BYTES {
				share[i] = rand::thread_rng().gen();
			}
			pub_shares[i] = share;
		}

		let entry = PlaintextShareStatusEntry {
			owner_id: rand::thread_rng().gen(),
			file_id: rand::thread_rng().gen(),
			published_shares: pub_shares,
			threshold: rand::thread_rng().gen(),
		};

		let key = speck::gen();

		let ciphertext_entry = entry.encrypt(key);
		let recovered = ciphertext_entry.decrypt(key);
		assert_eq!(recovered, entry);
	}

}

pub async fn download_share_status(db: &DynamoDB, file_id: FileID, owner_id: UserID, group_key: speck::Key) -> Result<PlaintextShareStatusEntry, DynamoError> {
	let ciphertext = db.download_status(file_id, owner_id).await?;
	Ok(ciphertext.decrypt(group_key))
}

pub async fn upload_share_status(db: &DynamoDB, entry: PlaintextShareStatusEntry, group_key: speck::Key) -> Result<(), DynamoError> {
	let ciphertext = entry.encrypt(group_key);
	db.upload_share_status(ciphertext.file_id, ciphertext.file_owner, ciphertext.encrypted_published_shares, ciphertext.encrypted_threshold).await
}

