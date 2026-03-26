#![cfg(test)]

use crate::{
    test_batch_operations::init_program, test_batch_operations::setup, test_batch_operations::Ctx,
    LockItem, ProgramData,
};
use soroban_sdk::{vec, String};

#[test]
fn test_program_archival_success() {
    let ctx = setup();
    let program_id = "PROG1";
    init_program(&ctx, program_id, 1000);

    // Initial state: not archived
    let info = ctx
        .client
        .get_program_info_v2(&String::from_str(&ctx.env, program_id));
    assert_eq!(info.total_funds, 1000);
    assert!(!info.archived);
    assert_eq!(info.archived_at, None);

    // Archive program
    ctx.client
        .archive_program(&String::from_str(&ctx.env, program_id));

    // After archival: archived is true
    let info = ctx
        .client
        .get_program_info_v2(&String::from_str(&ctx.env, program_id));
    assert!(info.archived);
    assert!(info.archived_at.is_some());

    // Check archived registry
    let archived = ctx.client.get_archived_programs();
    assert_eq!(archived.len(), 1);
    assert_eq!(
        archived.get(0).unwrap(),
        String::from_str(&ctx.env, program_id)
    );
}

#[test]
fn test_program_archival_filtering() {
    let ctx = setup();

    // 1. Singleton program
    // The setup function initializes the singleton program via initialize_contract if we call it...
    // Wait, setup() calls initialize_contract which doesn't create a program record.
    // We need to use init_program or similar.

    init_program(&ctx, "SINGLETON", 5000);

    // For singleton, we usually just use get_program_info
    let info = ctx.client.get_program_info();
    assert!(!info.archived);

    // Archive it (multi-program variant can archive singleton if IDs match)
    ctx.client
        .archive_program(&String::from_str(&ctx.env, "SINGLETON"));

    let info = ctx.client.get_program_info();
    assert!(info.archived);

    // Check list_programs (filters archived)
    let list = ctx.client.list_programs();
    assert_eq!(list.len(), 0);
}

#[test]
#[should_panic(expected = "Program not found")]
fn test_archive_non_existent_program() {
    let ctx = setup();
    ctx.client
        .archive_program(&String::from_str(&ctx.env, "NON_EXISTENT"));
}
