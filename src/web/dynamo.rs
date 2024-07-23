use core::panic;
use std::collections::HashMap;

use aws_sdk_dynamodb::{error::SdkError, operation::{delete_item::{DeleteItemError, DeleteItemOutput}, put_item::PutItemError, query::QueryError, scan::ScanError}, types::AttributeValue, Client};
use aws_sdk_s3::primitives::{Blob, SdkBody};
use aws_smithy_runtime_api::{client::result, http::Response};
use rusty_crypto::{lettuce, sha512};

use super::{messages::{EncryptedMessage, MessageID}, share_status::CiphertextShareStatusEntry, shares::{CiphertextShareEntry, FileID}, users::{self, UserEntry, UserID}};

/// An error that can occur during a DynamoDB request
#[derive(Debug)]
pub enum DynamoError {
	ScanError(SdkError<ScanError, Response<SdkBody>>),
	QueryError(SdkError<QueryError, Response<SdkBody>>),
	PutItemError(SdkError<PutItemError, Response<SdkBody>>),
	DeleteItemError(SdkError<DeleteItemError, Response<SdkBody>>)
}

/// A DynamoDB table
pub enum Table {
	Users,
	Messages,
	Shares,
	ShareStatus
}

impl Table {
	pub fn value(self) -> String {
		match self {
			Table::Users 		=> "users".to_string(),
			Table::Messages 	=> "messages".to_string(),
			Table::Shares 		=> "shares".to_string(),
			Table::ShareStatus 	=> "share_status".to_string()
		}
	}
}

/// The constant key values that are the "top row" of the database
pub enum TableKeyValues {
	Email,
	UserID,
	PublicKey,
	EncryptedSecretKey,
	MasterKeyHash,
	EncryptedSender,
	RecipientHash,
	EncryptedMessageContents,
	MessageIDKey,
	ShareOwnerID,
	EncryptedFileOwnerID,
	EncryptedFileID,
	EncryptedShare,
	FileOwner,
	FileID,
	PublishedShares,
	Threshold,
	EncryptedGroupKey
}

impl TableKeyValues {
	pub fn value(self) -> String {
		match self {
			TableKeyValues::Email => "email".to_string(),
			TableKeyValues::UserID => "user_id".to_string(),
			TableKeyValues::PublicKey => "public_key".to_string(),
			TableKeyValues::EncryptedSecretKey => "encrypted_secret_key".to_string(),
			TableKeyValues::MasterKeyHash => "master_key_hash".to_string(),
			TableKeyValues::EncryptedMessageContents => "contents".to_string(),
			TableKeyValues::EncryptedSender => "encrypted_sender".to_string(),
			TableKeyValues::RecipientHash => "recipient_id_hash".to_string(),
			TableKeyValues::MessageIDKey => "message_id".to_string(),
			TableKeyValues::ShareOwnerID => "share_owner_id".to_string(),
			TableKeyValues::EncryptedFileOwnerID => "encrypted_file_owner_id".to_string(),
			TableKeyValues::EncryptedFileID => "encrypted_file_id".to_string(),
			TableKeyValues::EncryptedShare => "encrypted_share".to_string(),
			TableKeyValues::FileOwner => "file_owner".to_string(),
			TableKeyValues::FileID => "file_id".to_string(),
			TableKeyValues::PublishedShares => "published_shares".to_string(),
			TableKeyValues::Threshold => "threshold".to_string(),
			TableKeyValues::EncryptedGroupKey => "encrypted_group_key".to_string()
		}
	}
}

/// A struct that acts as a simpler API for interacting with a DynamoDB database
pub struct DynamoDB {
	client: Client
}

macro_rules! attribute_num {
    ($x:expr) => {
        AttributeValue::N(format!("{}", $x))
    };
}
 
fn attribute_to_uid(attr: AttributeValue) -> UserID {
	UserID::from_str_radix(attr.as_n().unwrap(), 10).unwrap()
}

fn attribute_to_data(attr: AttributeValue) -> Vec<u8> {
	attr.as_b().unwrap().clone().into_inner()
}

impl UserEntry {

	/// Creates a UserEntry directly from the result 
	fn from_query_result(result: HashMap<String, AttributeValue>) -> Result<UserEntry, DynamoError> {
		Ok(
			UserEntry::new(
				attribute_to_uid(result.get(&TableKeyValues::UserID.value()).unwrap().clone()), 
				result.get(&TableKeyValues::Email.value()).unwrap().as_s().unwrap().to_string(), 
				attribute_to_data(result.get(&TableKeyValues::PublicKey.value()).unwrap().clone()).try_into().unwrap(), 
				attribute_to_data(result.get(&TableKeyValues::EncryptedSecretKey.value()).unwrap().clone()), 
				attribute_to_data(result.get(&TableKeyValues::MasterKeyHash.value()).unwrap().clone())
			)
		)
	}
}

impl EncryptedMessage {
	
	pub fn from_result(result: HashMap<String, AttributeValue>) -> EncryptedMessage {
		EncryptedMessage { 
			recipient_hash: result.get(&TableKeyValues::RecipientHash.value()).unwrap().as_b().unwrap().clone().into_inner().try_into().unwrap(), 
			encrypted_sender: result.get(&TableKeyValues::EncryptedSender.value()).unwrap().as_b().unwrap().clone().into_inner(), 
			message_id: attribute_to_uid(result.get(&TableKeyValues::MessageIDKey.value()).unwrap().clone()),
			encrypted_contents: result.get(&TableKeyValues::EncryptedMessageContents.value()).unwrap().as_b().unwrap().clone().into_inner()
		}
	}

}

impl CiphertextShareEntry {

	/// Creates a UserEntry directly from the result 
	fn from_query_result(result: HashMap<String, AttributeValue>) -> CiphertextShareEntry {
		CiphertextShareEntry::new(
			attribute_to_uid(result.get(&TableKeyValues::ShareOwnerID.value()).unwrap().clone()), 
			attribute_to_data(result.get(&TableKeyValues::EncryptedFileOwnerID.value()).unwrap().clone().try_into().unwrap()), 
			attribute_to_data(result.get(&TableKeyValues::EncryptedFileID.value()).unwrap().clone().try_into().unwrap()), 
			attribute_to_data(result.get(&TableKeyValues::EncryptedShare.value()).unwrap().clone().try_into().unwrap()),
			attribute_to_data(result.get(&TableKeyValues::EncryptedGroupKey.value()).unwrap().clone().try_into().unwrap())
		)
	}
}

impl CiphertextShareStatusEntry {

	fn from_query_result(result: HashMap<String, AttributeValue>) -> CiphertextShareStatusEntry {
		CiphertextShareStatusEntry { 
			file_owner: attribute_to_uid(result.get(&TableKeyValues::FileOwner.value()).unwrap().clone()), 
			file_id: attribute_to_uid(result.get(&TableKeyValues::FileID.value()).unwrap().clone()), 
			encrypted_published_shares: attribute_to_data(result.get(&TableKeyValues::PublishedShares.value()).unwrap().clone()), 
			encrypted_threshold: attribute_to_data(result.get(&TableKeyValues::Threshold.value()).unwrap().clone().try_into().unwrap())
		}
	}

}

impl DynamoDB {

	/// Initializes a DynamoDB client using the environment's config
	pub async fn new() -> DynamoDB {
		let config = aws_config::load_from_env().await;
		let client = Client::new(&config);
		DynamoDB { client }
	}

	// MARK: Users

	/// Returns Ok(true) if this user_id is in use, otherwise Ok(false) or an error
	pub async fn user_id_exists(&self, user_id: users::UserID) -> Result<bool, DynamoError> {
		let results = self.client
			.query()
			.table_name(Table::Users.value())
			.key_condition_expression("#uidk = :u")
			.expression_attribute_names("#uidk", TableKeyValues::UserID.value())
			.expression_attribute_values(":u", attribute_num!(user_id))
			.send()
			.await;

		let results = match results {
			Ok(r) => r,
			Err(e) => return Err(DynamoError::QueryError(e))
		};
	
		if let Some(items) = results.items {
			Ok(items.len() > 0)
		} else {
			panic!("Not sure how this happens")
		}
	}

	/// Returns Ok(true) if this email is in use, otherwise Ok(false) or an error
	pub async fn email_exists(&self, email: String) -> Result<bool, DynamoError> {
		let result: Result<Vec<_>, _> = self.client 
			.scan()
			.table_name(Table::Users.value())
			.filter_expression("#ek = :e")
			.expression_attribute_names("#ek", TableKeyValues::Email.value())
			.expression_attribute_values(":e", AttributeValue::S(email))
			.into_paginator()
			.items()
			.send()
			.collect()
			.await;

		let items = match result {
			Ok(r) => r,
			Err(e) => return Err(DynamoError::ScanError(e))
		};

		Ok(items.len() > 0)
	}

	/// Uploads user details
	pub async fn upload_user_info(&self, 
		user_id: users::UserID, 
		email: String, 
		public_key: lettuce::PublicKey, 
		encrypted_secret_key: Vec<u8>,
		master_key_hash: Vec<u8>
	) -> Result<(), DynamoError> {
		match self.client.put_item()
			.table_name(Table::Users.value())
			.item(TableKeyValues::Email.value(), AttributeValue::S(email))
			.item(TableKeyValues::UserID.value(), attribute_num!(user_id))
			.item(TableKeyValues::PublicKey.value(), AttributeValue::B(Blob::new(public_key))) 
			.item(TableKeyValues::EncryptedSecretKey.value(), AttributeValue::B(Blob::new(encrypted_secret_key)))
			.item(TableKeyValues::MasterKeyHash.value(), AttributeValue::B(Blob::new(master_key_hash)))
			.send().await {
				Ok(_) => Ok(()),
				Err(e) => Err(DynamoError::PutItemError(e)),
			}
	}

	/// Returns the user entry for a specific user_id
	pub async fn download_user_entry(&self, user_id: users::UserID) -> Result<users::UserEntry, DynamoError> {
		let result = match self.client.query()
			.table_name(Table::Users.value())
			.key_condition_expression("#uidk = :uid")
			.expression_attribute_names("#uidk", TableKeyValues::UserID.value())
			.expression_attribute_values(":uid", attribute_num!(user_id))
			.send()
			.await {
				Ok(r) => r,
				Err(e) => return Err(DynamoError::QueryError(e))
			};

		if let Some(items) = result.items {
			debug_assert!(items.len() == 1);
			let user_info = items[0].clone();

			UserEntry::from_query_result(user_info)
		} else {
			panic!("Something went wrong, maybe the user doesn't exist, we should check that!")
		}

	}

	/// Downloads the user entry associated with an email address
	/// Returns Ok(true) if this email is in use, otherwise Ok(false) or an error
	pub async fn download_user_for_email(&self, email: String) -> Result<UserEntry, DynamoError> {
		let result: Result<Vec<_>, _> = self.client 
			.scan()
			.table_name(Table::Users.value())
			.filter_expression("#ek = :e")
			.expression_attribute_names("#ek", TableKeyValues::Email.value())
			.expression_attribute_values(":e", AttributeValue::S(email))
			.into_paginator()
			.items()
			.send()
			.collect()
			.await;

		let items = match result {
			Ok(r) => r,
			Err(e) => return Err(DynamoError::ScanError(e))
		};

		UserEntry::from_query_result(items[0].clone())
	}

	// MARK: Messages

	/// Checks if a message ID exists
	pub async fn message_id_exists(&self, message_id: MessageID) -> Result<bool, DynamoError> {
		let result: Result<Vec<_>, _> = self.client 
			.scan()
			.table_name(Table::Messages.value())
			.filter_expression("#midk = :mid")
			.expression_attribute_names("#midk", TableKeyValues::MessageIDKey.value())
			.expression_attribute_values(":mid", attribute_num!(message_id))
			.into_paginator()
			.items()
			.send()
			.collect()
			.await;

		let items = match result {
			Ok(r) => r,
			Err(e) => return Err(DynamoError::ScanError(e))
		};

		Ok(items.len() > 0)
	}

	/// Upload (send) a message
	pub async fn upload_message(&self,
		recipient_hash: sha512::Digest,
		encrypted_sender: Vec<u8>,
		message_id: MessageID,
		encrypted_body: Vec<u8>
	) -> Result<(), DynamoError> {
		match self.client.put_item()
			.table_name(Table::Messages.value())
			.item(TableKeyValues::RecipientHash.value(), AttributeValue::B(Blob::new(recipient_hash.to_vec())))
			.item(TableKeyValues::EncryptedSender.value(), AttributeValue::B(Blob::new(encrypted_sender)))
			.item(TableKeyValues::MessageIDKey.value(), attribute_num!(message_id))
			.item(TableKeyValues::EncryptedMessageContents.value(), AttributeValue::B(Blob::new(encrypted_body)))
			.send().await {
				Ok(_) => Ok(()),
				Err(e) => Err(DynamoError::PutItemError(e))
			}
	}

	/// Returns a vector of messages to a certain user_id!
	pub async fn download_incoming_messages(&self, to_user: UserID) -> Result<Vec<HashMap<String, AttributeValue>>, DynamoError> {
		let recipient_hash = sha512::hash(users::u64_to_bytes(to_user));
		
		let result: Result<Vec<_>, _> = self.client.query()
			.table_name(Table::Messages.value())
			.key_condition_expression("#ridh_k = :ridh")
			.expression_attribute_names("#ridh_k", TableKeyValues::RecipientHash.value())
			.expression_attribute_values(":ridh", AttributeValue::B(Blob::new(recipient_hash)))
			.into_paginator()
			.items()
			.send()
			.collect()
			.await;

		let items = match result {
			Ok(r) => r,
			Err(e) => return Err(DynamoError::QueryError(e))
		};

		Ok(items)
	}

	/// Deletes a message entry
	pub async fn delete_message(&self, message_id: MessageID, recipient_id: UserID) -> Result<(), DynamoError> {
		match self.client.delete_item()
			.table_name(Table::Messages.value())
			.key(TableKeyValues::RecipientHash.value(), AttributeValue::B(Blob::new(sha512::hash(users::u64_to_bytes(recipient_id)))))
			.key(TableKeyValues::MessageIDKey.value(), attribute_num!(message_id))
			.send()
			.await {
				Ok(_) => Ok(()),
				Err(e) => Err(DynamoError::DeleteItemError(e))
			}
	}
	
	// MARK: Shares

	pub async fn upload_share(&self, share: CiphertextShareEntry) -> Result<(), DynamoError> {
		match self.client.put_item()
			.table_name(Table::Shares.value())
			.item(TableKeyValues::ShareOwnerID.value(), attribute_num!(share.share_owner_id))
			.item(TableKeyValues::EncryptedFileOwnerID.value(), AttributeValue::B(Blob::new(share.encrypted_file_owner_id)))
			.item(TableKeyValues::EncryptedFileID.value(), AttributeValue::B(Blob::new(share.encrypted_file_id)))
			.item(TableKeyValues::EncryptedShare.value(), AttributeValue::B(Blob::new(share.encrypted_share)))
			.item(TableKeyValues::EncryptedGroupKey.value(), AttributeValue::B(Blob::new(share.encrypted_group_key)))
			.send().await {
				Ok(_) => Ok(()),
				Err(e) => Err(DynamoError::PutItemError(e))
			}
	}

	pub async fn download_shares_for_user(&self, user_id: users::UserID) -> Result<Vec<CiphertextShareEntry>, DynamoError> {
		
		let results = match self.client.query()
			.table_name(Table::Shares.value())
			.key_condition_expression("#soid_k = :soid")
			.expression_attribute_names("#soid_k", TableKeyValues::ShareOwnerID.value())
			.expression_attribute_values(":soid", attribute_num!(user_id))
			.send()
			.await {
				Ok(r) => r,
				Err(e) => return Err(DynamoError::QueryError(e))
			};

		if let Some(items) = results.items {
			let results = items.iter().map(|item| CiphertextShareEntry::from_query_result(item.clone())).collect();
			Ok(results)
		} else {
			panic!("Not sure how this occurs")
		}
	}

	// MARK: Status

	pub async fn download_status(&self, file_id: FileID, owner_id: UserID) -> Result<CiphertextShareStatusEntry, DynamoError> {
		let results = match self.client.query()
			.table_name(Table::ShareStatus.value())
			.key_condition_expression("#fid_k = :fid and #uid_k = :uid")
			.expression_attribute_names("#fid_k", TableKeyValues::FileID.value())
			.expression_attribute_names("#uid_k", TableKeyValues::FileOwner.value())
			.expression_attribute_values(":fid", attribute_num!(file_id))
			.expression_attribute_values(":uid", attribute_num!(owner_id))
			.send()
			.await {
				Ok(r) => r,
				Err(e) => return Err(DynamoError::QueryError(e))
			};

		if let Some(items) = results.items {
			debug_assert_eq!(items.len(), 1, "There cannot be two share entries with the same user and file ID");
			Ok(CiphertextShareStatusEntry::from_query_result(items[0].clone()))
		} else {
			panic!("Whattt")
		}
	}

	pub async fn upload_share_status(&self, file_id: FileID, owner_id: UserID, encrypted_published_shares: Vec<u8>, encrypted_threshold: Vec<u8>) -> Result<(), DynamoError> {
		match self.client.put_item()
			.table_name(Table::ShareStatus.value())
			.item(TableKeyValues::FileOwner.value(), attribute_num!(owner_id))
			.item(TableKeyValues::FileID.value(), attribute_num!(file_id))
			.item(TableKeyValues::PublishedShares.value(), AttributeValue::B(Blob::new(encrypted_published_shares)))
			.item(TableKeyValues::Threshold.value(), AttributeValue::B(Blob::new(encrypted_threshold)))
			.send().await {
				Ok(_) => Ok(()),
				Err(e) => Err(DynamoError::PutItemError(e))
			}
	}
}
