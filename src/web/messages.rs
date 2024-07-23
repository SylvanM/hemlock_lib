use aws_sdk_dynamodb::types::AttributeValue;
use rand::Rng;
use rusty_crypto::{lettuce, secsharing::sharing::{Share256, SHARE_SIZE_BYTES}, sha512, speck};

use crate::web::shares::FileID;

use super::{dynamo::{self, DynamoDB}, shares::{self, CiphertextShareEntry}, users::{self, MasterKey, UserID}};

pub type MessageID = u64;

#[derive(Debug)]
pub enum MessagesError {
	DynamoError(dynamo::DynamoError),
	UsersError(users::UsersError),
	SharesError(shares::SharesError),
	NoSuchMessageID(MessageID)
}

impl From<shares::SharesError> for MessagesError {
	fn from(value: shares::SharesError) -> Self {
		MessagesError::SharesError(value)
	}
}

impl From<dynamo::DynamoError> for MessagesError {
	fn from(value: dynamo::DynamoError) -> Self {
		MessagesError::DynamoError(value)
	}
}

impl From<users::UsersError> for MessagesError {
	fn from(value: users::UsersError) -> Self {
		MessagesError::UsersError(value)
	}
}

#[derive(Debug, PartialEq)]
pub struct PlaintextMessage {
	pub recipient_hash: sha512::Digest,
	pub sender: UserID,
	pub message_id: MessageID,
	pub file_id: FileID,
	pub share: Share256,
	pub group_key: speck::Key
}

pub struct EncryptedMessage {
	pub recipient_hash: sha512::Digest,
	pub encrypted_sender: Vec<u8>,
	pub message_id: MessageID,
	pub encrypted_contents: Vec<u8>
}

impl EncryptedMessage {

	fn decrypt(&self, secret_key: lettuce::SecretKey) -> PlaintextMessage {
		let sender = users::bytes_to_u64(lettuce::dec(secret_key, self.encrypted_sender.clone()));
		let message_id = self.message_id;
		let recipient_hash = self.recipient_hash;

		let plaintext_contents = lettuce::dec(secret_key, self.encrypted_contents.clone());

		let file_id_bytes = plaintext_contents[0..8].to_vec();
		let group_key = plaintext_contents[8..40].try_into().unwrap();
		let share = plaintext_contents[40..].try_into().unwrap();

		let file_id = shares::bytes_to_fid(file_id_bytes);

		PlaintextMessage { 
			recipient_hash,
			sender, 
			message_id,
			file_id,
			share,
			group_key
		}
	}

}

impl PlaintextMessage {

	fn encrypt(&self, public_key: lettuce::PublicKey) -> EncryptedMessage {

		let encrypted_sender = lettuce::enc(public_key, users::u64_to_bytes(self.sender));
		let plaintext_contents = [shares::fid_to_bytes(self.file_id), self.group_key.to_vec(), self.share.to_vec()].concat();
		let encrypted_contents = lettuce::enc(public_key, plaintext_contents);

		EncryptedMessage { 
			recipient_hash: self.recipient_hash, 
			encrypted_sender: encrypted_sender, 
			message_id: self.message_id, 
			encrypted_contents: encrypted_contents
		}
	}
}

#[test]
fn test_encryption_symmetry() {
	for _ in 0..100 {
		// generate some random plaintexts!

		let mut rand_share: Share256 = [0 ; SHARE_SIZE_BYTES];
		for i in 0..SHARE_SIZE_BYTES {
			rand_share[i] = rand::thread_rng().gen();
		}

		let plaintext = PlaintextMessage {
			recipient_hash: sha512::hash(vec![rand::thread_rng().gen()]),
			sender: rand::thread_rng().gen(),
			message_id: rand::thread_rng().gen(),
			file_id: rand::thread_rng().gen(),
			share: rand_share,
			group_key: speck::gen()
		};

		let keys = lettuce::gen();

		assert_eq!(plaintext, (plaintext.encrypt(keys.public_key)).decrypt(keys.secret_key));
	}
}




/// Sends a share by encrypting it with the recipient's public key
pub async fn send_message(db: &DynamoDB, to_user: UserID, from_user: UserID, file_id: FileID, share: Share256, group_key: speck::Key) -> Result<(), MessagesError> {
	// first, we gather the keys needed!
	let recipient_public_key: lettuce::PublicKey = users::get_pubkey(db, to_user).await?;

	// now, come up with a unique message ID.

	let mut mid: MessageID;
	loop {
		mid = rand::thread_rng().gen();
		if !db.message_id_exists(mid).await? { break; }
	}

	let plaintext_message = PlaintextMessage {
		recipient_hash: sha512::hash(users::u64_to_bytes(to_user)),
		sender: from_user,
		file_id: file_id,
		message_id: mid,
		share: share,
		group_key: group_key
	};

	let encrypted_message = plaintext_message.encrypt(recipient_public_key);

	match db.upload_message(encrypted_message.recipient_hash, encrypted_message.encrypted_sender, encrypted_message.message_id, encrypted_message.encrypted_contents).await {
		Ok(_) => Ok(()),
		Err(e) => Err(MessagesError::DynamoError(e))
	}
}

/// Deletes a message ID from the inbox
async fn delete_message(db: &DynamoDB, message_id: MessageID, recipient: UserID) -> Result<(), MessagesError> {
	match db.message_id_exists(message_id).await {
		Ok(false) => Err(MessagesError::NoSuchMessageID(message_id)),
		Err(e) => Err(MessagesError::DynamoError(e)),
		Ok(true) => {
			db.delete_message(message_id, recipient).await?;

			Ok(())
		}
	}
}

/// Retrieves all incoming messages and uploads them as shares
pub async fn process_inbox(db: &DynamoDB, to_user: UserID, master_key: MasterKey) -> Result<(), MessagesError> {
	match db.download_incoming_messages(to_user).await {
		Err(e) => Err(MessagesError::DynamoError(e)),
		Ok(messages) => {
			// can we get our own secret key and decrypt it?

			let encrypted_secret_key = users::get_encrypted_secretkey(db, to_user).await?;
			let secret_key: lettuce::SecretKey = speck::dec_vec(master_key, encrypted_secret_key).try_into().unwrap();

			// Great!

			for m in messages {
				let plaintext_message = EncryptedMessage::from_result(m).decrypt(secret_key);
				// now, we need to create the share after re-encrypting it!

				debug_assert_eq!(plaintext_message.recipient_hash, sha512::hash(users::u64_to_bytes(to_user)));

				let encrypted_file_owner = speck::enc_vec(master_key, users::u64_to_bytes(plaintext_message.sender));
				let encrypted_file_id = speck::enc_vec(master_key, shares::fid_to_bytes(plaintext_message.file_id));
				let encrypted_share = speck::enc_vec(master_key, plaintext_message.share.to_vec());
				let encrypted_group_key = speck::enc_vec(master_key, plaintext_message.group_key.to_vec());

				let share = CiphertextShareEntry::new(to_user, encrypted_file_owner, encrypted_file_id, encrypted_share, encrypted_group_key);

				shares::upload_share(db, share).await?;

				// now, delete this message, signifying we successfully stored the share.
				delete_message(db, plaintext_message.message_id, to_user).await?;
				
			}	

			Ok(())
		}
	}
}