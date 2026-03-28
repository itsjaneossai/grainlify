use soroban_sdk::{contracttype, String, Vec};

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataCustomField {
    pub key: String,
    pub value: String,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProgramMetadata {
    pub program_name: Option<String>,
    pub program_type: Option<String>,
    pub ecosystem: Option<String>,
    pub tags: Vec<String>,
    pub start_date: Option<u64>,
    pub end_date: Option<u64>,
    pub custom_fields: Vec<MetadataCustomField>,
}
