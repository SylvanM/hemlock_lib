use std::{fs::File, iter::zip};

use rand::Rng;
use rusty_crypto::{secsharing::{self, sharing::Share256}, speck};

use crate::web::{self, dynamo::{self, DynamoError}, files::{self, FileError}, messages::{self, MessagesError}, share_status::{self, PlaintextShareStatusEntry}, shares::FileID, users::UserID};

#[derive(Debug)]
pub enum HemlockError {
	FileError(FileError),
	MessagesError(MessagesError),
	DynamoError(DynamoError),
	InsufficientPublishedShares
}

impl From<FileError> for HemlockError {
	fn from(value: FileError) -> Self {
		Self::FileError(value)
	}
}

impl From<DynamoError> for HemlockError {
	fn from(value: DynamoError) -> Self {
		Self::DynamoError(value)
	}
}

impl From<MessagesError> for HemlockError {
	fn from(value: MessagesError) -> Self {
		Self::MessagesError(value)
	}
}

/// The length of the ciphertext of a lettuce secret key, when encrypted with a speck key
pub const ENCRYPTED_SECRET_KEY_LEN: usize = 2432;

/// Takes a file, encrypts it using a randomly generated secret key, uploads the file to the file server, and sends the shares of 
/// the file to the desired parties. If `combiner_threshold` people recombine their keys, the original secret key
/// will be restored.
pub async fn split_and_share(file: &mut File, owner_id: UserID, combiner_threshold: usize, recipients: Vec<UserID>) -> Result<(), HemlockError> {
	let secret_key = speck::gen();
	let group_key = speck::gen();

	// we need to generate a UNIQUE file ID.
	// TODO: THIS IS INCORRECT. I am only writing this because the chance of a duplicate file ID are so tiny.
	// This does NOT SCALE and is ONLY for prototyping purposes. Instead, the approach used when creating a new 
	// user id should be used.
	let file_id: FileID = rand::thread_rng().gen();

	// go ahead and encrypt and upload the file.
	let files_client = files::make_client().await;
	web::files::encrypt_and_upload(&files_client, owner_id, file_id, secret_key, file).await?;

	// now, we split the key and send shares to the recipients!
	let shares = rusty_crypto::secsharing::sharing::distribute(combiner_threshold, recipients.len(), secret_key);

	let dynamo_client = dynamo::DynamoDB::new().await;

	for (share, recipient) in zip(shares, recipients) {
		messages::send_message(&dynamo_client, recipient, owner_id, file_id, share, group_key).await?;
	}

	// we also need to create an entry to keep track of the share!
	let share_status_entry = PlaintextShareStatusEntry {
		owner_id,
		file_id,
		published_shares: Vec::new(),
		threshold: combiner_threshold,
	};

	share_status::upload_share_status(&dynamo_client, share_status_entry, group_key).await?;

	Ok(())
}

/// Publishes a share for a certain file, given the group key
pub async fn publish_share(file_id: FileID, file_owner: UserID, share: Share256, group_key: speck::Key) -> Result<(), HemlockError> {
	// first, download the entry, and add to it!
	let client = dynamo::DynamoDB::new().await;
	let mut retrieved = share_status::download_share_status(&client, file_id, file_owner, group_key).await?;

	// make sure we don't publish the same share twice, that would be sillines!
	if !retrieved.published_shares.contains(&share) {
		retrieved.published_shares.push(share);
	}

	share_status::upload_share_status(&client, retrieved, group_key).await?;

	Ok(())
}

/// Attempts to recombine secrets into a file, if possible!
pub async fn recover_file(file_id: FileID, file_owner: UserID, group_key: speck::Key, file: &mut File) -> Result<(), HemlockError> {
	// check the published shares!
	let db = dynamo::DynamoDB::new().await;
	let files_client = files::make_client().await;

	let entry = share_status::download_share_status(&db, file_id, file_owner, group_key).await?;
	
	if entry.published_shares.len() < entry.threshold {
		return Err(HemlockError::InsufficientPublishedShares);
	}

	let recovered_secret_key = secsharing::sharing::reconstruct(entry.threshold, entry.published_shares);

	files::retrieve_file(&files_client, file_owner, file_id, recovered_secret_key, file).await?;

	Ok(())
}