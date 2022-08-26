use dash_spv_models::common::ChainType;
use dash_spv_primitives::crypto::byte_util::Reversable;
use dash_spv_primitives::hashes::hex::ToHex;
use crate::lib_tests::tests::block_height_for;
use crate::tests::mainnet_reload::load_masternode_lists_for_files;

#[test]
fn test_quorum_issue() {
    let chain = ChainType::MainNet;
    let files = vec![
        "MNL_0_1096704.dat".to_string(),
        "MNL_1096704_1097280.dat".to_string(),
        "MNL_1097280_1097856.dat".to_string(),
        "MNL_1097856_1098144.dat".to_string(),
        "MNL_1098144_1098432.dat".to_string(),
        "MNL_1098432_1098456.dat".to_string(),
        "MNL_1098456_1098480.dat".to_string(),
        "MNL_1098480_1098504.dat".to_string(),
        "MNL_1098504_1098528.dat".to_string(),
        "MNL_1098528_1098552.dat".to_string(),
        "MNL_1098552_1098576.dat".to_string(),
        "MNL_1098576_1098600.dat".to_string(),
        "MNL_1092576_1092600.dat".to_string(),
        "MNL_1092600_1092624.dat".to_string(),
        "MNL_1092624_1092648.dat".to_string(),
        "MNL_1092648_1092672.dat".to_string(),
        "MNL_1092672_1092696.dat".to_string(),
        "MNL_1092696_1092720.dat".to_string(),
        "MNL_1092720_1092744.dat".to_string(),
        "MNL_1092744_1092768.dat".to_string(),
        "MNL_1092768_1092792.dat".to_string(),
        "MNL_1092792_1092816.dat".to_string(),
        "MNL_1092816_1092840.dat".to_string(),
        "MNL_1092840_1092864.dat".to_string(),
        "MNL_1092864_1092888.dat".to_string(),
        "MNL_1098888_1098912.dat".to_string(),
        "MNL_1098912_1098936.dat".to_string(),
        "MNL_1098936_1098960.dat".to_string(),
        "MNL_1098960_1098984.dat".to_string(),
        "MNL_1098984_1099008.dat".to_string(),
    ];
    let (success, lists) = load_masternode_lists_for_files(files, chain, false);
    assert!(success, "Unsuccessful");
    lists.iter().for_each(|(hash, node)| {
        let h = block_height_for(chain, hash.clone().reversed().0.to_hex().as_str());
        println!("Testing quorum of masternode list at height {}", h);
    });

    // [chain.chainManager.masternodeManager reloadMasternodeListsWithBlockHeightLookup:blockHeightLookup];
    // for (NSData *masternodeListBlockHash in masternodeLists) {
    //     NSLog(@"Testing quorum of masternode list at height %u", blockHeightLookup(masternodeListBlockHash.UInt256));
    //     DSMasternodeList *originalMasternodeList = [masternodeLists objectForKey:masternodeListBlockHash];
    //     DSMasternodeList *reloadedMasternodeList = [chain.chainManager.masternodeManager masternodeListForBlockHash:masternodeListBlockHash.UInt256 withBlockHeightLookup:blockHeightLookup];
    //     XCTAssert(reloadedMasternodeList != nil, @"reloadedMasternodeList should exist");
    //     #define LOG_QUORUM_ISSUE_COMPARISON_RESULT 1
    //     if (!uint256_eq([originalMasternodeList masternodeMerkleRootWithBlockHeightLookup:blockHeightLookup], [reloadedMasternodeList calculateMasternodeMerkleRootWithBlockHeightLookup:blockHeightLookup])) {
    //         NSLog(@"%u original %@", blockHeightLookup(masternodeListBlockHash.UInt256), [originalMasternodeList toDictionaryUsingBlockHeightLookup:blockHeightLookup]);
    //         NSLog(@"%u reloaded %@", blockHeightLookup(masternodeListBlockHash.UInt256), [reloadedMasternodeList toDictionaryUsingBlockHeightLookup:blockHeightLookup]);
    //         NSDictionary *comparisonResult = [originalMasternodeList compare:reloadedMasternodeList usingOurString:@"original" usingTheirString:@"reloaded" blockHeightLookup:blockHeightLookup];
    //         NSLog(@"QUORUM_ISSUE_COMPARISON_RESULT %u %@", blockHeightLookup(masternodeListBlockHash.UInt256), comparisonResult);
    //     } else {
    //         #if LOG_QUORUM_ISSUE_COMPARISON_RESULT
    //         if ((blockHeightLookup(masternodeListBlockHash.UInt256)) == 1097280) {
    //             NSDictionary *comparisonResult = [originalMasternodeList compare:reloadedMasternodeList usingOurString:@"original" usingTheirString:@"reloaded" blockHeightLookup:blockHeightLookup];
    //             NSLog(@"QUORUM_ISSUE_COMPARISON_RESULT %u %@", blockHeightLookup(masternodeListBlockHash.UInt256), comparisonResult);
    //         }
    //         #endif
    //     }
    //     XCTAssertEqualObjects(uint256_hex([originalMasternodeList masternodeMerkleRootWithBlockHeightLookup:blockHeightLookup]), uint256_hex([reloadedMasternodeList calculateMasternodeMerkleRootWithBlockHeightLookup:blockHeightLookup]), @"These should be equal for height %d", originalMasternodeList.height);
    // }

    //   assert_eq!(lists.len(), 29, "There should be 29 masternode lists");
}
