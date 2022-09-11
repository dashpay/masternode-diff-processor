#[cfg(test)]
pub mod tests {
    extern crate libc;
    use crate::processing::processor_cache::MasternodeProcessorCache;
    use crate::processing::{MNListDiffResult, QRInfoResult};
    use crate::{
        process_mnlistdiff_from_message, processor_create_cache, register_processor,
        unwrap_or_diff_processing_failure, unwrap_or_qr_processing_failure, unwrap_or_return,
        MasternodeProcessor, ProcessingError,
    };
    use byte::BytesExt;
    use dash_spv_ffi::ffi::boxer::boxed;
    use dash_spv_ffi::ffi::from::FromFFI;
    use dash_spv_ffi::ffi::to::ToFFI;
    use dash_spv_ffi::ffi::unboxer::unbox_any;
    use dash_spv_ffi::types;
    use dash_spv_models::common::chain_type::ChainType;
    use dash_spv_models::common::LLMQType;
    use dash_spv_models::{llmq, masternode};
    use dash_spv_primitives::consensus::encode;
    use dash_spv_primitives::crypto::byte_util::{
        BytesDecodable, Reversable, UInt256, UInt384, UInt768,
    };
    use dash_spv_primitives::hashes::hex::{FromHex, ToHex};
    use std::collections::HashMap;
    use std::io::Read;
    use std::ptr::null_mut;
    use std::{env, fs, slice};

    #[derive(Debug)]
    pub struct FFIContext {
        pub chain: ChainType,
        pub cache: MasternodeProcessorCache,
    }

    pub struct AggregationInfo {
        pub public_key: UInt384,
        pub digest: UInt256,
    }
    /// This is convenience Core v0.17 method for use in tests which doesn't involve cross-FFI calls
    pub fn process_mnlistdiff_from_message_internal(
        message_arr: *const u8,
        message_length: usize,
        use_insight_as_backup: bool,
        genesis_hash: *const u8,
        processor: *mut MasternodeProcessor,
        cache: *mut MasternodeProcessorCache,
        context: *const std::ffi::c_void,
    ) -> MNListDiffResult {
        let processor = unsafe { &mut *processor };
        let cache = unsafe { &mut *cache };
        println!(
            "process_mnlistdiff_from_message_internal.start: {:?}",
            std::time::Instant::now()
        );
        processor.opaque_context = context;
        processor.use_insight_as_backup = use_insight_as_backup;
        processor.genesis_hash = genesis_hash;
        let message: &[u8] = unsafe { slice::from_raw_parts(message_arr, message_length as usize) };
        let list_diff =
            unwrap_or_diff_processing_failure!(llmq::MNListDiff::new(message, &mut 0, |hash| {
                processor.lookup_block_height_by_hash(hash)
            }));
        let result = processor.get_list_diff_result_internal_with_base_lookup(list_diff, cache);
        println!(
            "process_mnlistdiff_from_message_internal.finish: {:?} {:#?}",
            std::time::Instant::now(),
            result
        );
        result
    }

    /// This is convenience Core v0.18 method for use in tests which doesn't involve cross-FFI calls
    pub fn process_qrinfo_from_message_internal(
        message: *const u8,
        message_length: usize,
        use_insight_as_backup: bool,
        genesis_hash: *const u8,
        processor: *mut MasternodeProcessor,
        cache: *mut MasternodeProcessorCache,
        context: *const std::ffi::c_void,
    ) -> QRInfoResult {
        println!("process_qrinfo_from_message: {:?} {:?}", processor, cache);
        let message: &[u8] = unsafe { slice::from_raw_parts(message, message_length as usize) };
        let processor = unsafe { &mut *processor };
        processor.opaque_context = context;
        processor.use_insight_as_backup = use_insight_as_backup;
        processor.genesis_hash = genesis_hash;
        let cache = unsafe { &mut *cache };
        println!(
            "process_qrinfo_from_message --: {:?} {:?} {:?}",
            processor, processor.opaque_context, cache
        );
        let offset = &mut 0;
        let read_list_diff =
            |offset: &mut usize| processor.read_list_diff_from_message(message, offset);
        let mut process_list_diff = |list_diff: llmq::MNListDiff| {
            processor.get_list_diff_result_internal_with_base_lookup(list_diff, cache)
        };
        let read_snapshot = |offset: &mut usize| llmq::LLMQSnapshot::from_bytes(message, offset);
        let read_var_int = |offset: &mut usize| encode::VarInt::from_bytes(message, offset);
        let snapshot_at_h_c = unwrap_or_qr_processing_failure!(read_snapshot(offset));
        let snapshot_at_h_2c = unwrap_or_qr_processing_failure!(read_snapshot(offset));
        let snapshot_at_h_3c = unwrap_or_qr_processing_failure!(read_snapshot(offset));
        let diff_tip = unwrap_or_qr_processing_failure!(read_list_diff(offset));
        let diff_h = unwrap_or_qr_processing_failure!(read_list_diff(offset));
        let diff_h_c = unwrap_or_qr_processing_failure!(read_list_diff(offset));
        let diff_h_2c = unwrap_or_qr_processing_failure!(read_list_diff(offset));
        let diff_h_3c = unwrap_or_qr_processing_failure!(read_list_diff(offset));
        let extra_share = message.read_with::<bool>(offset, {}).unwrap_or(false);
        let (snapshot_at_h_4c, diff_h_4c) = if extra_share {
            (
                Some(unwrap_or_qr_processing_failure!(read_snapshot(offset))),
                Some(unwrap_or_qr_processing_failure!(read_list_diff(offset))),
            )
        } else {
            (None, None)
        };
        processor.save_snapshot(diff_h_c.block_hash, snapshot_at_h_c.clone());
        processor.save_snapshot(diff_h_2c.block_hash, snapshot_at_h_2c.clone());
        processor.save_snapshot(diff_h_3c.block_hash, snapshot_at_h_3c.clone());
        if extra_share {
            processor.save_snapshot(
                diff_h_4c.as_ref().unwrap().block_hash,
                snapshot_at_h_4c.as_ref().unwrap().clone(),
            );
        }
        let last_quorum_per_index_count =
            unwrap_or_qr_processing_failure!(read_var_int(offset)).0 as usize;
        let mut last_quorum_per_index: Vec<masternode::LLMQEntry> =
            Vec::with_capacity(last_quorum_per_index_count);
        for _i in 0..last_quorum_per_index_count {
            let entry = unwrap_or_qr_processing_failure!(masternode::LLMQEntry::from_bytes(
                message, offset
            ));
            last_quorum_per_index.push(entry);
        }
        let quorum_snapshot_list_count =
            unwrap_or_qr_processing_failure!(read_var_int(offset)).0 as usize;
        let mut quorum_snapshot_list: Vec<llmq::LLMQSnapshot> =
            Vec::with_capacity(quorum_snapshot_list_count);
        for _i in 0..quorum_snapshot_list_count {
            quorum_snapshot_list.push(unwrap_or_qr_processing_failure!(read_snapshot(offset)));
        }
        let mn_list_diff_list_count =
            unwrap_or_qr_processing_failure!(read_var_int(offset)).0 as usize;
        let mut mn_list_diff_list: Vec<MNListDiffResult> =
            Vec::with_capacity(mn_list_diff_list_count);
        for _i in 0..mn_list_diff_list_count {
            mn_list_diff_list.push(process_list_diff(unwrap_or_qr_processing_failure!(
                read_list_diff(offset)
            )));
        }
        // The order is important since the each new one dependent on previous
        let result_at_h_4c = if let Some(diff) = diff_h_4c {
            Some(process_list_diff(diff))
        } else {
            None
        };
        let result_at_h_3c = process_list_diff(diff_h_3c);
        let result_at_h_2c = process_list_diff(diff_h_2c);
        let result_at_h_c = process_list_diff(diff_h_c);
        let result_at_h = process_list_diff(diff_h);
        let result_at_tip = process_list_diff(diff_tip);
        QRInfoResult {
            error_status: ProcessingError::None,
            result_at_tip,
            result_at_h,
            result_at_h_c,
            result_at_h_2c,
            result_at_h_3c,
            result_at_h_4c,
            snapshot_at_h_c,
            snapshot_at_h_2c,
            snapshot_at_h_3c,
            snapshot_at_h_4c,
            extra_share,
            last_quorum_per_index,
            quorum_snapshot_list,
            mn_list_diff_list,
        }
    }

    pub fn init_block_store() -> HashMap<ChainType, HashMap<&'static str, u32>> {
        let mainnet: HashMap<&'static str, u32> = HashMap::from([
            (
                "000000000000000bf16cfee1f69cd472ac1d0285d74d025caa27cebb0fb6842f",
                1090392,
            ),
            (
                "000000000000000d6f921ffd1b48815407c1d54edc93079b7ec37a14a9c528f7",
                1090776,
            ),
            (
                "000000000000000c559941d24c167053c5c00aea59b8521f5cef764271dbd3c5",
                1091280,
            ),
            (
                "0000000000000003269a36d2ce1eee7753a2d2db392fff364f64f5a409805ca3",
                1092840,
            ),
            (
                "000000000000001a505b133ea44b594b194f12fa08650eb66efb579b1600ed1e",
                1090368,
            ),
            (
                "0000000000000006998d05eff0f4e9b6a7bab1447534eccb330972a7ef89ef65",
                1091424,
            ),
            (
                "000000000000001d9b6925a0bc2b744dfe38ff7da2ca0256aa555bb688e21824",
                1090920,
            ),
            (
                "000000000000000c22e2f5ca2113269ec62193e93158558c8932ba1720cea64f",
                1092648,
            ),
            (
                "0000000000000020019489504beba1d6197857e63c44da3eb9e3b20a24f40d1e",
                1092168,
            ),
            (
                "00000000000000112e41e4b3afda8b233b8cc07c532d2eac5de097b68358c43e",
                1088640,
            ),
            (
                "00000000000000143df6e8e78a3e79f4deed38a27a05766ad38e3152f8237852",
                1090944,
            ),
            (
                "0000000000000028d39e78ee49a950b66215545163b53331115e6e64d4d80328",
                1091184,
            ),
            (
                "00000000000000093b22f6342de731811a5b3fa51f070b7aac6d58390d8bfe8c",
                1091664,
            ),
            (
                "00000000000000037187889dd360aafc49d62a7e76f4ab6cd2813fdf610a7292",
                1092504,
            ),
            (
                "000000000000000aee08f8aaf8a5232cc692ef5fcc016786af72bd9b001ae43b",
                1090992,
            ),
            (
                "000000000000002395b6c4e4cb829556d42c659b585ee4c131a683b9f7e37706",
                1092192,
            ),
            (
                "00000000000000048a9b52e6f46f74d92eb9740e27c1d66e9f2eb63293e18677",
                1091976,
            ),
            (
                "000000000000001b4d519e0a9215e84c3007597cef6823c8f1c637d7a46778f0",
                1091448,
            ),
            (
                "000000000000001730249b150b8fcdb1078cd0dbbfa04fb9a18d26bf7a3e80f2",
                1092528,
            ),
            (
                "000000000000001c3073ff2ee0af660c66762af38e2c5782597e32ed690f0f72",
                1092072,
            ),
            (
                "000000000000000c49954d58132fb8a1c90e4e690995396be91d8f27a07de349",
                1092624,
            ),
            (
                "00000000000000016200a3f98e44f4b9e65da04b86bad799e6bbfa8972f0cead",
                1090080,
            ),
            (
                "000000000000000a80933f2b9b8041fdfc6e94b77ba8786e159669f959431ff2",
                1092600,
            ),
            (
                "00000000000000153afcdccc3186ad2ca4ed10a79bfb01a2c0056c23fe039d86",
                1092456,
            ),
            (
                "00000000000000103bad71d3178a6c9a2f618d9d09419b38e9caee0fddbf664a",
                1092864,
            ),
            (
                "000000000000001b732bc6d52faa8fae97d76753c8e071767a37ba509fe5c24a",
                1092360,
            ),
            (
                "000000000000001a17f82d76a0d5aa2b4f90a6e487df366d437c34e8453f519c",
                1091112,
            ),
            (
                "000000000000000caa00c2c24a385513a1687367157379a57b549007e18869d8",
                1090680,
            ),
            (
                "0000000000000022e463fe13bc19a1fe654c817cb3b8e207cdb4ff73fe0bcd2c",
                1091736,
            ),
            (
                "000000000000001b33b86b6a167d37e3fcc6ba53e02df3cb06e3f272bb89dd7d",
                1092744,
            ),
            (
                "0000000000000006051479afbbb159d722bb8feb10f76b8900370ceef552fc49",
                1092432,
            ),
            (
                "0000000000000008cc37827fd700ec82ee8b54bdd37d4db4319496977f475cf8",
                1091328,
            ),
            (
                "0000000000000006242af03ba5e407c4e8412ef9976da4e7f0fa2cbe9889bcd2",
                1089216,
            ),
            (
                "000000000000001dc4a842ede88a3cc975e2ade4338513d546c52452ab429ba0",
                1091496,
            ),
            (
                "0000000000000010d30c51e8ce1730aae836b00cd43f3e70a1a37d40b47580fd",
                1092816,
            ),
            (
                "00000000000000212441a8ef2495d21b0b7c09e13339dbc34d98c478cc51f8e2",
                1092096,
            ),
            (
                "00000000000000039d7eb80e1bbf6f7f0c43f7f251f30629d858bbcf6a18ab58",
                1090728,
            ),
            (
                "0000000000000004532e9c4a1def38cd71f3297c684bfdb2043c2aec173399e0",
                1091904,
            ),
            (
                "000000000000000b73060901c41d098b91f69fc4f27aef9d7ed7f2296953e407",
                1090560,
            ),
            (
                "0000000000000016659fb35017e1f6560ba7036a3433bfb924d85e3fdfdd3b3d",
                1091256,
            ),
            (
                "000000000000000a3c6796d85c8c49b961363ee88f14bff10c374cd8dd89a9f6",
                1092696,
            ),
            (
                "000000000000000f33533ba1c5d72f678ecd87abe7e974debda238c53b391737",
                1092720,
            ),
            (
                "000000000000000150907537f4408ff4a8610ba8ce2395faa7e44541ce2b6c37",
                1090608,
            ),
            (
                "000000000000001977d3a578e0ac3e4969675a74afe7715b8ffd9f29fbbe7c36",
                1091400,
            ),
            (
                "0000000000000004493e40518e7d3aff585e84564bcd80927f96a07ec80259cb",
                1092480,
            ),
            (
                "000000000000000df5e2e0eb7eaa36fcef28967f7f12e539f74661e03b13bdba",
                1090704,
            ),
            (
                "00000000000000172f1765f4ed1e89ba4b717a475e9e37124626b02d566d31a2",
                1090632,
            ),
            (
                "0000000000000018e62a4938de3428ddaa26e381139489ce1a618ed06d432a38",
                1092024,
            ),
            (
                "000000000000000790bd24e65daaddbaeafdb4383c95d64c0d055e98625746bc",
                1091832,
            ),
            (
                "0000000000000005f28a2cb959b316cd4b43bd29819ea07c27ec96a7d5e18ab7",
                1092408,
            ),
            (
                "00000000000000165a4ace8de9e7a4ba0cddced3434c7badc863ff9e237f0c8a",
                1091088,
            ),
            (
                "00000000000000230ec901e4d372a93c712d972727786a229e98d12694be9d34",
                1090416,
            ),
            (
                "000000000000000bf51de942eb8610caaa55a7f5a0e5ca806c3b631948c5cdcc",
                1092336,
            ),
            (
                "000000000000002323d7ba466a9b671d335c3b2bf630d08f078e4adee735e13a",
                1090464,
            ),
            (
                "0000000000000019db2ad91ab0f67d90df222ce4057f343e176f8786865bcda9",
                1091568,
            ),
            (
                "0000000000000004a38d87062bf37ef978d1fc8718f03d9222c8aa7aa8a4470f",
                1090896,
            ),
            (
                "0000000000000022c909de83351791e0b69d4b4be34b25c8d54c8be3e8708c87",
                1091592,
            ),
            (
                "0000000000000008f3dffcf342279c8b50e49c47e191d3df453fdcd816aced46",
                1092792,
            ),
            (
                "000000000000001d1d7f1b88d6518e6248616c50e4c0abaee6116a72bc998679",
                1092048,
            ),
            (
                "0000000000000020de87be47c5c10a50c9edfd669a586f47f44fa22ae0b2610a",
                1090344,
            ),
            (
                "0000000000000014d1d8d12dd5ff570b06e76e0bbf55d762a94d13b1fe66a922",
                1091760,
            ),
            (
                "000000000000000962d0d319a96d972215f303c588bf50449904f9a1a8cbc7c2",
                1089792,
            ),
            (
                "00000000000000171c58d1d0dbae71973530aa533e4cd9cb2d2597ec30d9b129",
                1091352,
            ),
            (
                "0000000000000004acf649896a7b22783810d5913b31922e3ea224dd4530b717",
                1092144,
            ),
            (
                "0000000000000013479b902955f8ba2d4ce2eb47a7f9f8f1fe477ec4b405bddd",
                1090512,
            ),
            (
                "000000000000001be0bbdb6b326c98ac8a3e181a2a641379c7d4308242bee90b",
                1092216,
            ),
            (
                "000000000000001c09a68353536ccb24b51b74c642d5b6e7e385cff2debc4e64",
                1092120,
            ),
            (
                "0000000000000013974ed8e13d0a50f298be0f2b685bfcfd8896172db6d4a145",
                1090824,
            ),
            (
                "000000000000001dbcd3a23c131fedde3acd6da89275e7f9fcae03f3107da861",
                1092888,
            ),
            (
                "000000000000000a8812d75979aac7c08ac69179037409fd7a368372edd05d23",
                1090872,
            ),
            (
                "000000000000001fafca43cabdb0c6385daffa8a039f3b44b9b17271d7106704",
                1090800,
            ),
            (
                "0000000000000006e9693e34fc55452c82328f31e069df740655b55dd07cb58b",
                1091016,
            ),
            (
                "0000000000000010e7c080046121900cee1c7de7fe063c7d81405293a9764733",
                1092384,
            ),
            (
                "0000000000000022ef41cb09a617d87c12c6841eea47310ae6a4d1e2702bb3d3",
                1090752,
            ),
            (
                "0000000000000017705efcdaefd6a1856becc0b915de6fdccdc9e149c1ff0e8f",
                1091856,
            ),
            (
                "0000000000000000265a9516f35dd85d32d103d4c3b95e81969a03295f46cf0c",
                1091952,
            ),
            (
                "0000000000000002dfd994409f5b6185573ce22eae90b4a1c37003428071f0a8",
                1090968,
            ),
            (
                "000000000000001b8d6aaa56571d987ee50fa2e2e9a28a8482de7a4b52308f25",
                1091136,
            ),
            (
                "0000000000000020635160b49a18336031af2d25d9a37ea211d514f196220e9d",
                1090440,
            ),
            (
                "000000000000001bfb2ac93ebe89d9831995462f965597efcc9008b2d90fd29f",
                1091784,
            ),
            (
                "000000000000000028515b4c442c74e2af945f08ed3b66f05847022cb25bb2ec",
                1091688,
            ),
            (
                "000000000000000ed6b9517da9a1df88d03a5904a780aba1200b474dab0e2e4a",
                1090488,
            ),
            (
                "000000000000000b44a550a61f9751601065ff329c54d20eb306b97d163b8f8c",
                1091712,
            ),
            (
                "000000000000001d831888fbd1899967493856c1abf7219e632b8e73f25e0c81",
                1091064,
            ),
            (
                "00000000000000073b62bf732ab8654d27b1296801ab32b7ac630237665162a5",
                1091304,
            ),
            (
                "0000000000000004c0b03207179143f028c07ede20354fab68c731cb02f95fc8",
                1090656,
            ),
            (
                "000000000000000df9d9376b9c32ea640ecfac406b41445bb3a4b0ee6625e572",
                1091040,
            ),
            (
                "00000000000000145c3e1b3bb6f53d5e2dd441ac41c3cfe48a5746c7b168a415",
                1092240,
            ),
            (
                "000000000000000d8bf4cade14e398d69884e991591cb11ee7fec49167e4ff85",
                1092000,
            ),
            (
                "000000000000001d098ef14fa032b33bcfc8e559351be8cd689e03c9678256a9",
                1091472,
            ),
            (
                "0000000000000000c25139a9227273eb7547a1f558e62c545e62aeb236e66259",
                1090584,
            ),
            (
                "0000000000000010785f105cc7c256b5365c597a9212e99beda94c6eff0647c3",
                1091376,
            ),
            (
                "0000000000000000fafe0f7314104d81ab34ebd066601a38e5e914f2b3cefce9",
                1092552,
            ),
            (
                "000000000000000ddbfad338961f2d900d62f1c3b725fbd72052da062704901c",
                1090848,
            ),
            (
                "000000000000000e5d9359857518aaf3685bf8af55c675cf0d17a45383ca297f",
                1091520,
            ),
            (
                "0000000000000012b444de0be31d695b411dcc6645a3723932cabc6b9164531f",
                1092916,
            ),
            (
                "000000000000001c414007419fc22a2401b07ab430bf433c8cdfb8877fb6b5b7",
                1092672,
            ),
            (
                "000000000000000355efb9a350cc76c7624bf42abea845770a5c3adc2c5b93f4",
                1092576,
            ),
            (
                "000000000000000f327555478a9d580318cb6e15db059642eff84797bf133196",
                1091808,
            ),
            (
                "0000000000000003b3ea97e688f1bec5f95930950b54c1bb01bf67b029739696",
                1091640,
            ),
            (
                "000000000000001a0d96dbc0cac26e445454dd2506702eeee7df6ff35bdcf60e",
                1091544,
            ),
            (
                "000000000000001aac60fafe05124672b19a1c3727dc17f106f11295db1053a3",
                1092288,
            ),
            (
                "000000000000000e37bca1e08dff47ef051199f24e9104dad85014c323464069",
                1091208,
            ),
            (
                "0000000000000013dd0059e5f701a39c0903e7f16d393f55fc896422139a4291",
                1092768,
            ),
            (
                "000000000000000f4c8d5bdf6b89435d3a9789fce401286eb8f3f6eeb84f2a1d",
                1091160,
            ),
            (
                "000000000000001414ff2dd44ee4c01c02e6867228b4e1ff490f635f7de949a5",
                1091232,
            ),
            (
                "0000000000000013b130038d0599cb5a65165fc03b1b38fe2dd1a3bad6e253df",
                1092312,
            ),
            (
                "00000000000000082cb9d6d169dc625f64a6a24756ba796eaab131a998b42910",
                1091928,
            ),
            (
                "0000000000000001e358bce8df79c24def4787bf0bf7af25c040342fae4a18ce",
                1091880,
            ),
        ]);
        let tesnet = HashMap::from([
            (
                "0000000007697fd69a799bfa26576a177e817bc0e45b9fcfbf48b362b05aeff2",
                72000,
            ),
            (
                "0000000004c19db86b34bc9b5288b5af2aaff507e8474fa2db99e1ea03bacdfe",
                122328,
            ),
            (
                "000000000282ab23f92f5b517325e8da93ae470a9de3fe3aeebfcaa54cb48155",
                122352,
            ),
            (
                "000000000bca30e387a942d9dbcf6ad2273ab6061c50e5dc8282c6ff73cc3c99",
                122376,
            ),
            (
                "0000000000bee166c1c3194f50f667900319e1fd9666aef8ec4a10accfbf3df3",
                122400,
            ),
            (
                "000000000a7c1dfff2586d2a635dd9b8ae491aae1b6ca72bc9070d1bd0cd50bc",
                122424,
            ),
            (
                "00000000094f05e8cbf8c8fca55f688f4fbb6ec3624dbda9eab1039f005e64de",
                122448,
            ),
            (
                "000000000b6e93b1c97696e5de41fb3e9b94fab2df5654c1c2ddad636a6a85e3",
                122472,
            ),
            (
                "0000000003d2d2527624d1509885f0ab3d38d476d67c6fe0da7f5df8c460a675",
                122520,
            ),
            (
                "000000000108e218babaca583a3bc69f1273e6468e7eb27078da6374cdf14bb8",
                122544,
            ),
            (
                "000000000ce60869ccd9258c81307a71457581d4ce0f8e684aeda300a481d9a5",
                122568,
            ),
            (
                "0000000002738de17d2db957ddbdd207d66c2e8977ba8d7d8da541b67d4eb0fa",
                122592,
            ),
            (
                "0000000003bb193de9431c474ac0247bc20cfc2a318084329ea88fc642b554e3",
                122616,
            ),
            (
                "0000000002ef3d706192992b6823ed1c6221a794d1225346c97c7a3d75c88b3f",
                122640,
            ),
            (
                "00000000054437d43f5d12eaa4898d8b85e8521b1897674ee847f070045669ad",
                122664,
            ),
            (
                "0000000002ed5b13979a23330c5e219ea530ae801293df74d38c6cd6e7be78b9",
                122688,
            ),
            (
                "0000000003a583ca0e218394876ddce04a94274add270c24ebd21b6570b0b202",
                122712,
            ),
            (
                "000000000525063bee5e6935224a03d160b21965bba60320802c8f3201d0ebae",
                122736,
            ),
            (
                "000000000d201a317e82baaf536f889c83b62add5bd0375744ce1ee77e3d099f",
                122760,
            ),
            (
                "0000000006221f59fb1bc78200724447db51545cc43ffd5a78eed78106bbdb1a",
                122784,
            ),
            (
                "0000000015f89c20b07c7e6a5df001bd9838a1eee4d33a1468860daeab8d2ba3",
                122808,
            ),
            (
                "0000000006cb4b5de2a176af028d859a1499a384f8c88f243f81f01bbc729c91",
                122832,
            ),
            (
                "000000000821a7211313a614aa3f4379af7870a38740a770d7baffd3bb6578e9",
                122856,
            ),
            (
                "0000000008e87f07d3d1abbaa196d68cd4bf7b19ef0ddb0cbbcf1eb86f7aea46",
                122880,
            ),
            (
                "0000000009b4a670292967a9cd8da4ecad05586179a60e987a9b71b2c3ea1a58",
                122904,
            ),
            (
                "0000000001d975dfc73df9040e894576f27f6c252f1540b1c092c80353cdb823",
                122928,
            ),
            (
                "0000000003b852d8331f850491aeca3d91b43b3ef7af8208c82814c0e06cd75c",
                122952,
            ),
            (
                "0000000005938a06c7e88a5cd3a950655bde3ed7046e9ffad542ad5902395d2b",
                122976,
            ),
            (
                "000000000577855d5599ce9a89417628233a6ccf3a86b2938b191f3dfed2e63d",
                123000,
            ),
        ]);
        let mut h = HashMap::new();
        h.insert(ChainType::MainNet, mainnet);
        h.insert(ChainType::TestNet, tesnet);
        h
    }

    pub fn block_height_for(chain: ChainType, key: &str) -> u32 {
        match chain {
            ChainType::MainNet => match key {
                "00000ffd590b1485b3caadc19b22e6379c733355108f107a430458cdf3407ab6" => 0,
                "000000000000000bf16cfee1f69cd472ac1d0285d74d025caa27cebb0fb6842f" => 1090392,
                "000000000000000d6f921ffd1b48815407c1d54edc93079b7ec37a14a9c528f7" => 1090776,
                "000000000000000c559941d24c167053c5c00aea59b8521f5cef764271dbd3c5" => 1091280,
                "0000000000000003269a36d2ce1eee7753a2d2db392fff364f64f5a409805ca3" => 1092840,
                "000000000000001a505b133ea44b594b194f12fa08650eb66efb579b1600ed1e" => 1090368,
                "0000000000000006998d05eff0f4e9b6a7bab1447534eccb330972a7ef89ef65" => 1091424,
                "000000000000001d9b6925a0bc2b744dfe38ff7da2ca0256aa555bb688e21824" => 1090920,
                "000000000000000c22e2f5ca2113269ec62193e93158558c8932ba1720cea64f" => 1092648,
                "0000000000000020019489504beba1d6197857e63c44da3eb9e3b20a24f40d1e" => 1092168,
                "00000000000000112e41e4b3afda8b233b8cc07c532d2eac5de097b68358c43e" => 1088640,
                "00000000000000143df6e8e78a3e79f4deed38a27a05766ad38e3152f8237852" => 1090944,
                "0000000000000028d39e78ee49a950b66215545163b53331115e6e64d4d80328" => 1091184,
                "00000000000000093b22f6342de731811a5b3fa51f070b7aac6d58390d8bfe8c" => 1091664,
                "00000000000000037187889dd360aafc49d62a7e76f4ab6cd2813fdf610a7292" => 1092504,
                "000000000000000aee08f8aaf8a5232cc692ef5fcc016786af72bd9b001ae43b" => 1090992,
                "000000000000002395b6c4e4cb829556d42c659b585ee4c131a683b9f7e37706" => 1092192,
                "00000000000000048a9b52e6f46f74d92eb9740e27c1d66e9f2eb63293e18677" => 1091976,
                "000000000000001b4d519e0a9215e84c3007597cef6823c8f1c637d7a46778f0" => 1091448,
                "000000000000001730249b150b8fcdb1078cd0dbbfa04fb9a18d26bf7a3e80f2" => 1092528,
                "000000000000001c3073ff2ee0af660c66762af38e2c5782597e32ed690f0f72" => 1092072,
                "000000000000000c49954d58132fb8a1c90e4e690995396be91d8f27a07de349" => 1092624,
                "00000000000000016200a3f98e44f4b9e65da04b86bad799e6bbfa8972f0cead" => 1090080,
                "000000000000000a80933f2b9b8041fdfc6e94b77ba8786e159669f959431ff2" => 1092600,
                "00000000000000153afcdccc3186ad2ca4ed10a79bfb01a2c0056c23fe039d86" => 1092456,
                "00000000000000103bad71d3178a6c9a2f618d9d09419b38e9caee0fddbf664a" => 1092864,
                "000000000000001b732bc6d52faa8fae97d76753c8e071767a37ba509fe5c24a" => 1092360,
                "000000000000001a17f82d76a0d5aa2b4f90a6e487df366d437c34e8453f519c" => 1091112,
                "000000000000000caa00c2c24a385513a1687367157379a57b549007e18869d8" => 1090680,
                "0000000000000022e463fe13bc19a1fe654c817cb3b8e207cdb4ff73fe0bcd2c" => 1091736,
                "000000000000001b33b86b6a167d37e3fcc6ba53e02df3cb06e3f272bb89dd7d" => 1092744,
                "0000000000000006051479afbbb159d722bb8feb10f76b8900370ceef552fc49" => 1092432,
                "0000000000000008cc37827fd700ec82ee8b54bdd37d4db4319496977f475cf8" => 1091328,
                "0000000000000006242af03ba5e407c4e8412ef9976da4e7f0fa2cbe9889bcd2" => 1089216,
                "000000000000001dc4a842ede88a3cc975e2ade4338513d546c52452ab429ba0" => 1091496,
                "0000000000000010d30c51e8ce1730aae836b00cd43f3e70a1a37d40b47580fd" => 1092816,
                "00000000000000212441a8ef2495d21b0b7c09e13339dbc34d98c478cc51f8e2" => 1092096,
                "00000000000000039d7eb80e1bbf6f7f0c43f7f251f30629d858bbcf6a18ab58" => 1090728,
                "0000000000000004532e9c4a1def38cd71f3297c684bfdb2043c2aec173399e0" => 1091904,
                "000000000000000b73060901c41d098b91f69fc4f27aef9d7ed7f2296953e407" => 1090560,
                "0000000000000016659fb35017e1f6560ba7036a3433bfb924d85e3fdfdd3b3d" => 1091256,
                "000000000000000a3c6796d85c8c49b961363ee88f14bff10c374cd8dd89a9f6" => 1092696,
                "000000000000000f33533ba1c5d72f678ecd87abe7e974debda238c53b391737" => 1092720,
                "000000000000000150907537f4408ff4a8610ba8ce2395faa7e44541ce2b6c37" => 1090608,
                "000000000000001977d3a578e0ac3e4969675a74afe7715b8ffd9f29fbbe7c36" => 1091400,
                "0000000000000004493e40518e7d3aff585e84564bcd80927f96a07ec80259cb" => 1092480,
                "000000000000000df5e2e0eb7eaa36fcef28967f7f12e539f74661e03b13bdba" => 1090704,
                "00000000000000172f1765f4ed1e89ba4b717a475e9e37124626b02d566d31a2" => 1090632,
                "0000000000000018e62a4938de3428ddaa26e381139489ce1a618ed06d432a38" => 1092024,
                "000000000000000790bd24e65daaddbaeafdb4383c95d64c0d055e98625746bc" => 1091832,
                "0000000000000005f28a2cb959b316cd4b43bd29819ea07c27ec96a7d5e18ab7" => 1092408,
                "00000000000000165a4ace8de9e7a4ba0cddced3434c7badc863ff9e237f0c8a" => 1091088,
                "00000000000000230ec901e4d372a93c712d972727786a229e98d12694be9d34" => 1090416,
                "000000000000000bf51de942eb8610caaa55a7f5a0e5ca806c3b631948c5cdcc" => 1092336,
                "000000000000002323d7ba466a9b671d335c3b2bf630d08f078e4adee735e13a" => 1090464,
                "0000000000000019db2ad91ab0f67d90df222ce4057f343e176f8786865bcda9" => 1091568,
                "0000000000000004a38d87062bf37ef978d1fc8718f03d9222c8aa7aa8a4470f" => 1090896,
                "0000000000000022c909de83351791e0b69d4b4be34b25c8d54c8be3e8708c87" => 1091592,
                "0000000000000008f3dffcf342279c8b50e49c47e191d3df453fdcd816aced46" => 1092792,
                "000000000000001d1d7f1b88d6518e6248616c50e4c0abaee6116a72bc998679" => 1092048,
                "0000000000000020de87be47c5c10a50c9edfd669a586f47f44fa22ae0b2610a" => 1090344,
                "0000000000000014d1d8d12dd5ff570b06e76e0bbf55d762a94d13b1fe66a922" => 1091760,
                "000000000000000962d0d319a96d972215f303c588bf50449904f9a1a8cbc7c2" => 1089792,
                "00000000000000171c58d1d0dbae71973530aa533e4cd9cb2d2597ec30d9b129" => 1091352,
                "0000000000000004acf649896a7b22783810d5913b31922e3ea224dd4530b717" => 1092144,
                "0000000000000013479b902955f8ba2d4ce2eb47a7f9f8f1fe477ec4b405bddd" => 1090512,
                "000000000000001be0bbdb6b326c98ac8a3e181a2a641379c7d4308242bee90b" => 1092216,
                "000000000000001c09a68353536ccb24b51b74c642d5b6e7e385cff2debc4e64" => 1092120,
                "0000000000000013974ed8e13d0a50f298be0f2b685bfcfd8896172db6d4a145" => 1090824,
                "000000000000001dbcd3a23c131fedde3acd6da89275e7f9fcae03f3107da861" => 1092888,
                "000000000000000a8812d75979aac7c08ac69179037409fd7a368372edd05d23" => 1090872,
                "000000000000001fafca43cabdb0c6385daffa8a039f3b44b9b17271d7106704" => 1090800,
                "0000000000000006e9693e34fc55452c82328f31e069df740655b55dd07cb58b" => 1091016,
                "0000000000000010e7c080046121900cee1c7de7fe063c7d81405293a9764733" => 1092384,
                "0000000000000022ef41cb09a617d87c12c6841eea47310ae6a4d1e2702bb3d3" => 1090752,
                "0000000000000017705efcdaefd6a1856becc0b915de6fdccdc9e149c1ff0e8f" => 1091856,
                "0000000000000000265a9516f35dd85d32d103d4c3b95e81969a03295f46cf0c" => 1091952,
                "0000000000000002dfd994409f5b6185573ce22eae90b4a1c37003428071f0a8" => 1090968,
                "000000000000001b8d6aaa56571d987ee50fa2e2e9a28a8482de7a4b52308f25" => 1091136,
                "0000000000000020635160b49a18336031af2d25d9a37ea211d514f196220e9d" => 1090440,
                "000000000000001bfb2ac93ebe89d9831995462f965597efcc9008b2d90fd29f" => 1091784,
                "000000000000000028515b4c442c74e2af945f08ed3b66f05847022cb25bb2ec" => 1091688,
                "000000000000000ed6b9517da9a1df88d03a5904a780aba1200b474dab0e2e4a" => 1090488,
                "000000000000000b44a550a61f9751601065ff329c54d20eb306b97d163b8f8c" => 1091712,
                "000000000000001d831888fbd1899967493856c1abf7219e632b8e73f25e0c81" => 1091064,
                "00000000000000073b62bf732ab8654d27b1296801ab32b7ac630237665162a5" => 1091304,
                "0000000000000004c0b03207179143f028c07ede20354fab68c731cb02f95fc8" => 1090656,
                "000000000000000df9d9376b9c32ea640ecfac406b41445bb3a4b0ee6625e572" => 1091040,
                "00000000000000145c3e1b3bb6f53d5e2dd441ac41c3cfe48a5746c7b168a415" => 1092240,
                "000000000000000d8bf4cade14e398d69884e991591cb11ee7fec49167e4ff85" => 1092000,
                "000000000000001d098ef14fa032b33bcfc8e559351be8cd689e03c9678256a9" => 1091472,
                "0000000000000000c25139a9227273eb7547a1f558e62c545e62aeb236e66259" => 1090584,
                "0000000000000010785f105cc7c256b5365c597a9212e99beda94c6eff0647c3" => 1091376,
                "0000000000000000fafe0f7314104d81ab34ebd066601a38e5e914f2b3cefce9" => 1092552,
                "000000000000000ddbfad338961f2d900d62f1c3b725fbd72052da062704901c" => 1090848,
                "000000000000000e5d9359857518aaf3685bf8af55c675cf0d17a45383ca297f" => 1091520,
                "0000000000000012b444de0be31d695b411dcc6645a3723932cabc6b9164531f" => 1092916,
                "000000000000001c414007419fc22a2401b07ab430bf433c8cdfb8877fb6b5b7" => 1092672,
                "000000000000000355efb9a350cc76c7624bf42abea845770a5c3adc2c5b93f4" => 1092576,
                "000000000000000f327555478a9d580318cb6e15db059642eff84797bf133196" => 1091808,
                "0000000000000003b3ea97e688f1bec5f95930950b54c1bb01bf67b029739696" => 1091640,
                "000000000000001a0d96dbc0cac26e445454dd2506702eeee7df6ff35bdcf60e" => 1091544,
                "000000000000001aac60fafe05124672b19a1c3727dc17f106f11295db1053a3" => 1092288,
                "000000000000000e37bca1e08dff47ef051199f24e9104dad85014c323464069" => 1091208,
                "0000000000000013dd0059e5f701a39c0903e7f16d393f55fc896422139a4291" => 1092768,
                "000000000000000f4c8d5bdf6b89435d3a9789fce401286eb8f3f6eeb84f2a1d" => 1091160,
                "000000000000001414ff2dd44ee4c01c02e6867228b4e1ff490f635f7de949a5" => 1091232,
                "0000000000000013b130038d0599cb5a65165fc03b1b38fe2dd1a3bad6e253df" => 1092312,
                "00000000000000082cb9d6d169dc625f64a6a24756ba796eaab131a998b42910" => 1091928,
                "0000000000000001e358bce8df79c24def4787bf0bf7af25c040342fae4a18ce" => 1091880,
                "0000000000000005f05fa51e0552ca6e46780be550da7230cd2d02f8ed4506ef" => 1097808,
                "000000000000000faf2cac0d4b6b64fc168c3febe54a56a7ffc395cff98a9197" => 1097208,
                "00000000000000096d80e8274bea062831d5befafae221dfcfd3717ce6cf6014" => 1098576,
                "00000000000000123be8fccf32a966f94362e7676ff22e3fffc5acd0564478de" => 1096392,
                "000000000000001d33b9dd2600867da9b4dceb9393bc5352d157dc0755255ae6" => 1096224,
                "000000000000001aaa7a0a09708d929587fc17ff20e67cbd961e4661c210cd55" => 1098288,
                "0000000000000005b792156d43ece54c07684f25a3bc68535635a168270c164f" => 1098408,
                "000000000000000cb19c621f3f6f31890cfe20e96de7f07c7cc87df6e76c0fdb" => 1096248,
                "000000000000000a4f7cd4fbdd47a1a3dabc82b7f48c5a47340c2440decd1ad1" => 1098264,
                "000000000000001b6423cb52fefd813e6263dda5fd8e4f611c87c4c10f9efd63" => 1098120,
                "000000000000000d81a502004fa824e8864fe72cce5e441c94e70781a1d5c248" => 1098912,
                "000000000000002043543aca7a30d6ce95c030e51734341fdd2a8473eb07c4fc" => 1098216,
                "00000000000000125044156d05c1b5309521483a76786cb549748b78bc1dd885" => 1096176,
                "0000000000000008f5ae5a32a484eb829f78eece049e70395de65f0d03e20dd6" => 1097448,
                "000000000000001168a451504cc254c531a006a77d707a279fbe9dd51a65acda" => 1096824,
                "0000000000000017b0ee941a07532c47c814ec751854b551e3da2bf8addfc7da" => 1096776,
                "000000000000000fc7af431ccc9374589ade89b86b826a38b0b36cadb2a0bdbf" => 1096464,
                "00000000000000086edc17d34df01f002195a5d737063324f3e46930c57350b2" => 1096896,
                "000000000000000812756367b7f38cc27ca1ac63f26c7ee81248be99b8a399fe" => 1096944,
                "00000000000000226c79b8624a3b2855d8b84bc68a0b0f8461026e7cada81d4a" => 1096368,
                "000000000000000e8cd9d448061b1a8198ad4741707b8d01a23b5b71cd7f5688" => 1097784,
                "00000000000000037258bba0d30a803fd73fc60d27ce93b9f1293b52c78aa35f" => 1097592,
                "000000000000001c7361f82e8da3d6a7fb34ad5ae4dde3ddcc1d9ddba8cafd39" => 1097664,
                "000000000000000a37f2a18828ab4d27d2c1aae5e05a606ddba526750c024cd9" => 1096416,
                "00000000000000015f263e5713680e8c256120ec739828028aa4124e1463f939" => 1096536,
                "000000000000000dd632855f6ed62d0a421e9fbb6a4ef3a9b28aebf1af65e98b" => 1098552,
                "0000000000000004586e94967e381843192f972678f1a1f58c4dde5e99d8fc44" => 1097328,
                "0000000000000018534d3aae537bf48656883e4f441e0bd28670347cc5d0d6b1" => 1097232,
                "0000000000000019112283be4f21b455b53a1b2ca7c04d4df4db64dc5eaf33e9" => 1096344,
                "00000000000000120b56f64ed6c173562a814fef9cdb223f98ceb71ec0721453" => 1098816,
                "000000000000001cc3f58f03c176be5a1aa858358d90d28396f5f14a5841dfc8" => 1096296,
                "000000000000002021e36a9eb14321eea04df8c2d9f5a98aba4ae110811a265a" => 1098360,
                "000000000000000080cc4309a7447bb9ece31700769dc379572d22e45798fa2f" => 1098168,
                "0000000000000002d799bd937089094546ea6910362cdde13305a190cc228966" => 1097760,
                "000000000000000d02d05da2fa63761aebc1dc6ad313da63b10809026aa32012" => 1096632,
                "0000000000000016174a372e62c8c18817df356487d539135ead487ecec8d276" => 1097160,
                "000000000000000b62b169b3621aca12f2a4b1faa5443e52c435118f0a185a1a" => 1098768,
                "000000000000000e5458bc47813b49b23d3a3f015bd74628e1950bc51086891b" => 1094976,
                "000000000000001a7eaa4cb338614eaa498c87171a5459c35b1879267896a8b8" => 1096728,
                "000000000000000cf068c8605300fa6eaabf1cd72f0baa91ebbfc7f615efffb0" => 1097904,
                "000000000000000a7db9d1cb6e97587548d12f9b15e1d7217c3bb9fc5f7aca62" => 1096992,
                "00000000000000120aa3e7d582a37cd1ba9e33f7255643886dfce934e608f588" => 1098144,
                "0000000000000006859c3d9a085c3bbe1aada948f6d573af21b41c68e66b9ac8" => 1098840,
                "00000000000000199f543a7d3e9f6372d950721a88a9a10aa92917c7a663695b" => 1098672,
                "00000000000000184ffe2c87ee0e8046b630bbb67e8708a59d78a501c22f7ead" => 1096440,
                "00000000000000128cc9aebae3ea0753103e4c53286b2370e1dab2655ce68b19" => 1098528,
                "0000000000000000fd8021168f6be48e6c1444e29f85fa72c654b4f616c071f6" => 1098312,
                "0000000000000017693260e70c48015796efdbf6cfb36c3ed16a0ce0aa72110e" => 1097520,
                "000000000000001ffbd9b2b064b32e64c6d3a3dae13780a8f67dd8123a52f824" => 1096680,
                "000000000000000b08d1bcf29d13fc4cb8972420979a7cca01bb3e76e848b341" => 1097880,
                "00000000000000138ee64cdd6c5c9eb641be56002a08cc4da3947c9a8427b811" => 1097424,
                "00000000000000022ba51a9c85c3f2908e050e251031c127c379ed4c84dc3995" => 1098024,
                "00000000000000069501469ea47bdc919909737c7ae881cb0048dc7406a547f4" => 1098432,
                "000000000000001d396bfa004a77bc6a590ebd4e62c3be62e17c9f9183b6b2a6" => 1097472,
                "000000000000000e5442292206c610d87af06af00500a22b3bf478d3ac05ab65" => 1098984,
                "000000000000001212cd887e2064e0fef2efe30efad366a3043ac618c8d1f7e0" => 1097136,
                "0000000000000017dd8f722b72713df020c25cd8bb189e1516fbb97f91712276" => 1098000,
                "0000000000000017bb50e264cebfec81804847bb19b759e1deed6d5ccd54af70" => 1096488,
                "000000000000000076e6e626df28690678d026dcb7655433cb77cbbce4585ab9" => 1097352,
                "000000000000000b0e12838219dce4ee33bd3ebf148a6655cdef57f5ac74dec1" => 1098744,
                "000000000000000ee7034001ad0ed7040a4a55a388824624b2770154cb7b2778" => 1098480,
                "0000000000000002ae77e6e7922c995ab76163717382c2290699125b017aeb83" => 1096608,
                "000000000000000e40f843520b37a0299e0f73c03cc09e20e1f7e1d15db0eac3" => 1097496,
                "000000000000000931d7809849ee2c0520274565043c91011abab799484c2990" => 1097304,
                "0000000000000000049b8adab54f72710bf6d897597766529325c713de86b5e4" => 1098648,
                "000000000000002156a89bfcb10462994d1d0953b418583140f2874b84a750ca" => 1097256,
                "0000000000000012d25cbba3536d24aa5cc53c622eeac03c65412383147f4394" => 1099008,
                "000000000000000787490f469efdfb1dbf6b86150b86c48f127f7653211b2c41" => 1098096,
                "000000000000000a3a980aec3a4421b54dbbb407f30ee949c13e3665cc372009" => 1098624,
                "000000000000001fb0ced1479e7d15e7efed4b92b1d5ec43a1da297e8dc64a1e" => 1097376,
                "0000000000000016f526c58ea7a5ba4091426d3d9d11434ef422cd6cbfa0a4d1" => 1098960,
                "00000000000000057f1c57f1183758044c52c33ddd6b8ab2171afcb980062117" => 1096560,
                "000000000000000c595ba7f4da46fb33fdfb5cbff49a5af1536de6baaf364658" => 1098240,
                "0000000000000023382f4fda810321271b8d5b32fc5c0a8ae82d6e35e73ea7d5" => 1097064,
                "000000000000001ad5328d0a3c97209bbbca4bb35d76119a8ac0231a36aa75c9" => 1097280,
                "00000000000000106c3b9664269e2a92d53266f5485f24266e61d12f902f85ea" => 1098720,
                "0000000000000018925fd95309371243ef4df332801968084363af572f6c5d45" => 1097616,
                "0000000000000011038e77a86801cb5f05047d45e57b8a95b715f7f5bed2ac70" => 1096272,
                "000000000000000f7943a003184c5e99b5951fa80d80d6585721e1819b046617" => 1096512,
                "000000000000000e0e3a7248d77f94d3013cae7b27090941a944926683c7126c" => 1096152,
                "000000000000000acc62d1c58e0cf316573ca248fcaefc98f77619d227d93413" => 1096320,
                "0000000000000012b1e0582fa3c805bb15ebab29792766815ea008254395aebf" => 1096848,
                "0000000000000016f620befa318c8b40bc5d9a955121261af09ac8ddeef93e5e" => 1097088,
                "0000000000000017ae9d4db3c6e6fdf7827824423caa4599219f3af795ec6404" => 1096704,
                "0000000000000013fea89dca12ca39a3250bab6ff979c682b44c968892e7844e" => 1095840,
                "000000000000000c43df820465cf30f4e9d8a38330c5f7c4fcb90780aa88df38" => 1096656,
                "0000000000000006b8f4ccbf679f3f5744d879c02851a361ef7e1e0ed9d57e18" => 1097016,
                "000000000000001ad3de1c97c51b31072ea54380034b01bdf7da610b77f75189" => 1098048,
                "000000000000001efb6b66a1cd0f2c6a41c9a820db8fc5de159aa186a09a4ce2" => 1098936,
                "00000000000000005d2b5286b448a25d9c2006849d41fb0c9c4bb3bb8724c42d" => 1098864,
                "0000000000000008997ba7c5b584a4dbffd17a8b5cd08cae51e7e6371f0ec3ca" => 1098696,
                "0000000000000022a46ff5bb17d406fa821f70aa80c2b9aa37bc21edaea2569a" => 1098072,
                "00000000000000125d8731954a9c15b86b34e78c1fbe2ca29bd3a99f38462689" => 1098888,
                "0000000000000016ad254676362d6cad62acaa1f9900b6c951cfd73303fa0356" => 1098792,
                "0000000000000020d7ac24b497e420c8eeb9de5ba55a4a204130dda9e09fc85a" => 1097568,
                "000000000000001e3c72bec566addb499b9f633effe8cb4f1ddab303fa155d13" => 1097544,
                "00000000000000143c121d0ebcc8ac6d22f5f2bf44b1b871569dec0e4df7c69c" => 1095552,
                "000000000000001e1c9372e3d2db633498af3c900f87de1c5f19ed05a0df4072" => 1097736,
                "00000000000000185588f0dcad30cbe720b5bc67abfae54e64d9f92e1e0b2d22" => 1097040,
                "000000000000000185765bff94d5da02e62261ab2366d2ccaa0d86685c0485de" => 1097976,
                "000000000000000557d8eb6ecdf684f3b7f3219794047ac4f44eff0d9bfbdb7b" => 1097184,
                "00000000000000063d1eabcc5c29a51c0aa354b758b33e70f722f78c46741342" => 1096200,
                "00000000000000134b8226f8db668803ee6abcfe4df2809b36de36205bd80227" => 1096920,
                "000000000000001afbb65ce325134464e74de2c9e1f67c61501c434e82514094" => 1097688,
                "000000000000000178d6cb5792aea8a9e51a716df4b20018761509dddd881b6b" => 1097112,
                "0000000000000020eeb077e77f9e3e60975e2a7426b6084ff8ad5ca43ef17c41" => 1096968,
                "000000000000000db1e46a7e9890b842506e2775fd4723fbbe2d420609087f21" => 1096128,
                "00000000000000029151942416b68ff4aada689b12e47cc09ce7b802ded57505" => 1096800,
                "000000000000001c5cdb520ddc3ec0511790352f6177d5e598656f83690bd734" => 1096584,
                "0000000000000012bf85edb70e524a05c56644b0bdb0ce4a2d6d12739463c52b" => 1096752,
                "000000000000000e5535ad543a6bfb463bc8f0636aac6a3e7f79683b7c94bf6f" => 1097832,
                "0000000000000010404aecc04aff5a2be47a5c6caeeea32160df9fe8c47511ed" => 1097856,
                "0000000000000001cf3f3937abd607c9ab0a50a354edf3614378aca4fb8fdf5e" => 1098384,
                "00000000000000157572263a4b5a3c7a22f10c66c423be1d5a51aa24bc9f724b" => 1097400,
                "000000000000001dcf7e0c3a9130750540511e0cf631ea2f81aac7617c821755" => 1098504,
                "00000000000000071e19fd57488218254d12b773d3a7f8b2dc53b9d45805c9a8" => 1096872,
                "00000000000000095ea3c8e00a43086c7d5f6ececc6642721f733eb27229ff86" => 1097712,
                "000000000000000eb3238f4d8a2f95b0a4692548b6547cf495e4ce790e61d2b5" => 1098192,
                "0000000000000016570cdc593f871223b3aec795c1049c2d40c702925e0d2800" => 1098456,
                "00000000000000169f9688971408aadfd3159740d11b9f504719ceaafe117a26" => 1098600,
                "0000000000000000cfd7003a6aa0b1e0ae1c556a9b83a064771e2ba5a4668169" => 1097640,
                "00000000000000247cb10a7d823736b672866e1d015ce1446a9e0b3c87eb25e5" => 1098336,
                "000000000000001df6026dcd49b32b8cda38807cc475d6868679e6eb77e5edf4" => 1097952,
                "000000000000000e78706ecf6d744a2edc5143d3325ade22940dc14ccfd3f938" => 1094400,
                _ => u32::MAX,
            },
            ChainType::TestNet => match key {
                "00000bafbc94add76cb75e2ec92894837288a481e5c005f6563d91623bf8bc2c" => 0,
                "0000000007697fd69a799bfa26576a177e817bc0e45b9fcfbf48b362b05aeff2" => 72000,
                "0000000004c19db86b34bc9b5288b5af2aaff507e8474fa2db99e1ea03bacdfe" => 122328,
                "000000000282ab23f92f5b517325e8da93ae470a9de3fe3aeebfcaa54cb48155" => 122352,
                "000000000bca30e387a942d9dbcf6ad2273ab6061c50e5dc8282c6ff73cc3c99" => 122376,
                "0000000000bee166c1c3194f50f667900319e1fd9666aef8ec4a10accfbf3df3" => 122400,
                "000000000a7c1dfff2586d2a635dd9b8ae491aae1b6ca72bc9070d1bd0cd50bc" => 122424,
                "00000000094f05e8cbf8c8fca55f688f4fbb6ec3624dbda9eab1039f005e64de" => 122448,
                "000000000b6e93b1c97696e5de41fb3e9b94fab2df5654c1c2ddad636a6a85e3" => 122472,
                "0000000003d2d2527624d1509885f0ab3d38d476d67c6fe0da7f5df8c460a675" => 122520,
                "000000000108e218babaca583a3bc69f1273e6468e7eb27078da6374cdf14bb8" => 122544,
                "000000000ce60869ccd9258c81307a71457581d4ce0f8e684aeda300a481d9a5" => 122568,
                "0000000002738de17d2db957ddbdd207d66c2e8977ba8d7d8da541b67d4eb0fa" => 122592,
                "0000000003bb193de9431c474ac0247bc20cfc2a318084329ea88fc642b554e3" => 122616,
                "0000000002ef3d706192992b6823ed1c6221a794d1225346c97c7a3d75c88b3f" => 122640,
                "00000000054437d43f5d12eaa4898d8b85e8521b1897674ee847f070045669ad" => 122664,
                "0000000002ed5b13979a23330c5e219ea530ae801293df74d38c6cd6e7be78b9" => 122688,
                "0000000003a583ca0e218394876ddce04a94274add270c24ebd21b6570b0b202" => 122712,
                "000000000525063bee5e6935224a03d160b21965bba60320802c8f3201d0ebae" => 122736,
                "000000000d201a317e82baaf536f889c83b62add5bd0375744ce1ee77e3d099f" => 122760,
                "0000000006221f59fb1bc78200724447db51545cc43ffd5a78eed78106bbdb1a" => 122784,
                "0000000015f89c20b07c7e6a5df001bd9838a1eee4d33a1468860daeab8d2ba3" => 122808,
                "0000000006cb4b5de2a176af028d859a1499a384f8c88f243f81f01bbc729c91" => 122832,
                "000000000821a7211313a614aa3f4379af7870a38740a770d7baffd3bb6578e9" => 122856,
                "0000000008e87f07d3d1abbaa196d68cd4bf7b19ef0ddb0cbbcf1eb86f7aea46" => 122880,
                "0000000009b4a670292967a9cd8da4ecad05586179a60e987a9b71b2c3ea1a58" => 122904,
                "0000000001d975dfc73df9040e894576f27f6c252f1540b1c092c80353cdb823" => 122928,
                "0000000003b852d8331f850491aeca3d91b43b3ef7af8208c82814c0e06cd75c" => 122952,
                "0000000005938a06c7e88a5cd3a950655bde3ed7046e9ffad542ad5902395d2b" => 122976,
                "000000000577855d5599ce9a89417628233a6ccf3a86b2938b191f3dfed2e63d" => 123000,

                "000000339cd97d45ee18cd0cba0fd590fb9c64e127d3c30885e5b7376af94fdf" => 338688,

                "0000000e6d15a11825211c943c4a995c44ebb2b0834b7848c2e080b48ca0148e" => 417600,
                "0000006faac9003919a6d5456a0a46ae10db517f572221279f0540b79fd9cf1b" => 417888,
                "000000bd5639c21dd8abf60253c3fe0343d87a9762b5b8f57e2b4ea1523fd071" => 418176,
                "000000dc07d722238a994116c3395c334211d9864ff5b37c3be51d5fdda66223" => 418464,

                "000000007c66872df531661924bdf55ac55fbb8bad864a0b586195d7e9eacfbe" => 795194,
                "0000003ed4ca9d2beaa2787a75306c428a961b9029ea9e824d34143c8baed6eb" => 795196,
                "0000008c8b021e9d1600ed24f05df949e1f8b3b7e26c64a186bc4fa5c74f9777" => 795198,

                "00000089f3e36310e62e45cda9851eb238b22c68fb889864f901bd567880d6af" => 795456,
                "00000130390747eb54e83384af2e0bbb08478af9d1cc0827cb861d383e723bcf" => 795457,
                "00000122846046e646442eeca685c7f33457d95852ec8a6e757d8b0fdb39e922" => 795458,
                "0000012f2efde692f00838e0ecce763b1c2d07e3c8c7c26eab3919f53c4cc11d" => 795459,
                "000001be2d535c22a027cade8255d306d8fcbe7b803e890e3d14de94abe03025" => 795460,
                "000001962c491ab69746a382daa3316baeb7f4389d290d3f430e9d0b6704cf89" => 795461,
                "000001a6db475ab483af7612bfebb772c8b496747e7ec942f0b1124260089b25" => 795462,
                "000000104f8b37bd8702b0513d35a8e03b1ba8cb0c7c49302d7271684cb35cc0" => 795463,
                "00000183fcd446e892c2cd2bb469d0e7a04f7fe2df25c1ce6556999089110a4e" => 795464,
                "000000f1c48213466ef6dbf591423c3406aad1e77af9d09f8ca208a340bcd7e6" => 795465,
                "00000155ddb55b3fb8d48b94d57f1bdbbca5be0b1910cf8fae5cf61f67ee8df6" => 795466,
                "000000929c81a2c4a3b319eb3d8c08850389f316ac35d8a3071052854e984ad2" => 795467,
                "0000010e0821e8b3579699f60456981bbd4b5a5b0f7243ac76034da55ccc9867" => 795468,
                "000001672a25662cab9686731993e7dc805318cba225c9ed88db74e1878c0ff2" => 795469,
                "00000282421d62ea10ab73d1b42dc4d815b8fe5e8e42fee7ce94a1555f7c2118" => 795470,
                "00000052faf061a6ffdbaf24ea89f7e147a4c05d4fcd584c6fae6c3999bf1c73" => 795471,
                "000000675a22f42f2e47ca425d93a9e7f0b15b1e60965b88c9f8163813b46745" => 795472,
                "0000015f6e4fffce8a9edf9f8ea7da11ef8cdaa55ea60b224ff5c666c876d05e" => 795473,
                "000001181dc7144439b50a96aa95a2abc3109904693ef4ffcddc4a7ec160484e" => 795474,
                "000002299ea82cb7d55e45d966f39c6d93c620aff1a213ae70b31fd6c3ba7ad4" => 795475,
                "00000097ea8f2fa459b95cab9c4d2cb38db89d65cf63dddad7ef4733602eb59a" => 795476,
                "000001c96452cc7e2656f89a8e6070f35b0da18503ccbef6283ec5fc2be20696" => 795477,
                "0000001b585e3283da2e0e417107fccbf2e4948f727fd4e1ddcfcebfdf3a8394" => 795478,
                "0000020390f28e28d21fd0ffd068132e80cb4c462b7d312fb2e52e908b1d6ebf" => 795479,
                "000000e4cf5e6fd2e28edcf32324de02c1303f6d947b5078596794d5dee4f13e" => 795480,
                "000000165d22d3ba67d1b50359e211e93e7d50f463d0aa62a413846e6429032a" => 795481,
                "00000021e77d571c820baa70acefbb8f0cb21f303033a8e8ae798c49e397ea59" => 795483,
                "000000beddafdbc64dc73e8c5686fc21fe9e6e3f063b2abdd6bd728c09be1078" => 795485,
                "000000021f2631ff2cb96d07ad256d4ea4ecb0adb34da5dd08cac42f5d43369a" => 795487,

                "0000021c387334151438c59551967d61eb68788a5327ce15b39238933d8fa366" => 795736,
                "00000008a98566d40a33df98f81475b3617d0210513b0d346d70a09db11b418f" => 795744,
                "00000011e147a05e2ec74fabb50e7b3b851f934822911f7881ed3744862f7fc7" => 795745,
                "0000010e2a60f68f15852871ffa1b172446b7b0417ba1fe9f1cf02c87f5e8e80" => 795746,
                "00000092ff29dd460330f31ef11f71dad4e0d396b7f20f5bfe061d5ee20c052f" => 795747,
                "0000005c378747888b6ae2d77ec3dd9367f947f12018bd1ba15c0f8555908bd4" => 795748,
                "000000cc12b15edd201514f0276550a279e7e464aac0569929bd19c80c195b96" => 795749,
                "000000753101b81e6e8cbd498cfeff30be53145cd65ab7c5880e13f614d101e3" => 795750,
                "00000177bc633e308107df48b79875ee006453a3f0452e16edc35e2ebb658624" => 795751,
                "000001840841c7d29c9e96f2357568afea1ddaf1986f897300a5a1b97bf22e82" => 795752,
                "00000030a584a58b08f73586546730f2b6b9b8eac0285ac86bccebb026e1c091" => 795754,
                "000000e097ebcdaaa8eed4951398085972fe74aed2d95305394f6276bb6be8cd" => 795755,
                "000000c4b7daf878adda6fa2a5513ba43bc49f30701e98e4d02c9bffb7fdc053" => 795756,
                "0000003ad48c33b90a606e616e9c767f58cd8aec3cd4124f1eeb1657adf12988" => 795757,
                "000001a584c0c85af34aa18693590beb6d0b3f8ce67d94cf49d802c4a865ec14" => 795759,
                "0000007ddc70e209f35dab03cced4f1804dab628b187170ae3688624d6796c02" => 795760,
                "000000e18a6b72aa8cc87e76a2adfb9290cbe29135a0368cc6456bd988e17487" => 795761,
                "000001494faaaf1dee26a81f33ae3e8afa1049f9edc77f85c4107ec72cac2fbc" => 795762,
                "0000010833f17104bd366c62dcc2cd18aefec3dfc5e68a92a08bfc6f97ba1a9b" => 795763,
                "00000113b3f9f40af0257aabff61d6a8c078bacbdd4dabbfe427b442e7bd2baa" => 795764,
                "000000d4fcb401767f9364369bae5f363a645037897403e9b546a25dbe6aa409" => 795766,
                "0000050bd2c07ad0c2dac45d46da4a5c8e533d25ca4bdd64fbac8e8492ad35a4" => 795767,
                "000002151526cbd9aaa94b7d51ca1e454cef16539da85cc1b920f5c00ee662d3" => 795768,
                "0000000df8a2133e82141335e24c8987dd8515e252473d75a1353e84c2facd40" => 795772,
                "000001e21c332228709ffac4956f8827dbb2bf87afbc14285d9fee5ebb8b2b80" => 795773,
                "00000151738b297451fdbcad0feb69efaf08ad0d000c6a0abea32178e464c9d7" => 795774,
                "00000020bf25d1f6f1ffc657eb87e3b303b2f74d6b6373d2722bb5c9e7ab6e11" => 795775,

                "000000628ef83a2ddf93736e802835f515adea6c81e9bdecbf4d67416ad19f35" => 796024,
                "000001347b87a72a206b15e928e761acc056c2027d57f0b9ca610d6e718f3c8a" => 796032,
                "000000685d4e30a12b39e7d5b9ed567bafa28ee7f877f432b721a916f1cbeacc" => 796033,
                "0000007511cd212ffdc40d282d881d161fa036c9a9ba9aa2e945b1f7311045f7" => 796034,
                "000001e4eda0bf443d9da022bc3093fbcef6298b80142426be410989ebc489d1" => 796037,
                "00000129e61a471c4989d066c53c5a85fdf966b461283f5ad2034b59c2b90227" => 796038,
                "00000265455c2a0e0ec316a52403a58c22425005ec718aeb5d666a4c9d9fb4a6" => 796042,
                "000001e4930577edf08dd1fd80a9c405a4ffd0aca918b2fdaaf3603210d51e86" => 796043,
                "0000020abcaf3d97b5216c43dfd99f7c4ece37621135c096cf000f1b0547dbe1" => 796044,
                "00000216ce5a1dbf593d1964b73e202fef39fb6bff74224414203da31d30c56c" => 796047,
                "00000ad663efff0492e52a292d0de114a595d9dd35e3cddc2bf1716895799919" => 796048,
                "0000012168ef0f0376ced3363321739b7d8f00529830ca6e56eec052f606d278" => 796050,
                "000000b6682621dfecaee08c05044d8e8cbd21df25dcbe6fd758e2cd968bbb83" => 796053,
                "0000004203f66dbabe24a753e112cdcb18a0d62f1010d99566fef2f512c6e95c" => 796056,
                "00000153f4e819d0296e3150e512df8ab44f8f1281f4e46acda682549745e922" => 796058,
                "000001746bc8d6d07ce5b386c8159f8e1b03f27562e705c72b072f5304a79f26" => 796059,
                "000000b00746d8c37214238097afb3afe3fd430c7f0d35d5aece95ccf4c3b56c" => 796062,
                "000001d4c0cea44b11fb0a59442f056602d6cddcc3c96d5b9d080e05e9818427" => 796063,

                "00000083985b597ede56529b30f57afcd5a2fccf0e560bff286d645555b90610" => 796128,
                "000001e5e0bf1f5eae6398bf50e61bd91d19f90c0874c72f12f10dcda08f7332" => 796152,
                "00000476320723b68f3887b554e6647856e3ea3f63d854c6671d9f0f5c07ae3c" => 796176,

                "00000048ad66a799ecc5cc0957bd204a1fb38b1f1aa0f03988b51ea854e6d261" => 796200,
                "00000059577616d4006caf47e1c99ed65f21afabfeab8ef75022cc5a1a83754c" => 796224,
                "000000863322c7a56d861e3ed7e0fab1eb9b1a5ca040fa3241c3c668cfa23a4e" => 796248,
                "0000016ab1d8029a3af1df2d9b1be8d0765a9cc4f58ec876ec65ccece5c6d321" => 796272,
                "000000735d7fb29433a564b7d793fc59ea9999d347470fd2db8d40554e9fc183" => 796296,

                "000003b03c38daf45ec2dea558ac2faac07945abdfe172a23ead6ec3594f96b0" => 796312,
                "000001cce4bda8328bf8da24c309e8e5a850cec80326a23d07f7c398984d2f99" => 796320,
                "000001b8724f2fb446e7d778885f6e6b1b5ba01a854e0b248e5d44b810b4f568" => 796321,
                "0000022e90798a7e3ae8a0c54ff1b08bcbd3c28814cb0d13c87ede05525d5d85" => 796322,
                "0000027132beb45ce081b1df336bf24c56b98738685d4284af59f4e60a91995a" => 796323,
                "000002614a99ce9ff3510df256ce8d2048e8166a169e2fdbe4b7c63da2bafccf" => 796324,
                "0000003a47674b80950b61ee6b140c9df9fe53be227ada3e099414aa4bc33b6a" => 796325,
                "000002aa86c37f9b82e3365032d327b5bb9daf937f17f7aebeaa60e7a81b2bbb" => 796326,
                "0000015a4f68bccf833fbe01dfcd4dc8762ae9bfc3c8522962d77c4111ff7cc7" => 796327,
                "00000289e003c83a1f439ec76f60006b6e498f02c271568426594ef13281fb7f" => 796328,
                "0000028230d4354fa9ad7ba1a1f78ac4bbe80030422b79a9389cc21091f739a6" => 796329,
                "0000023bc5d4ded8f55db044e1359986707b142d85e8b565df8ccd01a77f167a" => 796330,
                "000002e80e4b1558dc73cda6ab4127629a4be4108f1743686276ed873b53a043" => 796331,
                "00000273c475ae0a1e38347d193b078e049714b547512da5cb759d8169d3f96a" => 796332,
                "00000189428c95a92f8d95b671d406cdf6cebf88d2f7979b61bc38b47209fabd" => 796333,
                "000000c995037312ca175def1a71d49d8dba81ad793dc48a64429055cf156232" => 796334,
                "00000103314490b095dad78c6d4367c8b8aa539e487017f90cbae6f975bdd23d" => 796335,
                "000000c0eeab1b13900de9b62415c6daf4e132ebc70de9d2de345642265c6a8a" => 796336,
                "000001bfb8acbba17de7eee1685ea8de819759009b0191d1fe81713541b93917" => 796337,
                "000001a217a8261066939e15de47a33417d273256036d98c5a6151d5b2e32355" => 796338,
                "000001758fca4893ede279449590d682a90454cbb64c3d89f1c06d8e5cfd21c0" => 796339,
                "00000181b6f51bf646b9fb70ea9d2aaf5e628d1b5553fd185dc239f658d5d520" => 796340,
                "000000b62e9791022f4879807dce5977050be824298442a53599305578a56971" => 796341,
                "00000274d33b97e254f97fce65edd39739a0ba2aaab5ccd0283a29dc9b96bd01" => 796342,
                "000001aece0279ab21b7503ffbb5ef72640fb33efc0a33cacb3217b802dabf84" => 796343,
                "00000148cff107be072ca972fdfcc92335054fb89be7419cac279961ed8d9fc4" => 796344,
                "000000d9d53f91daf99bf559281ecc84720fcc072a4d04eccd5e2c1a45b89398" => 796345,
                "000000c3a23206c0edb6bda518bb79a489a6b2df360d2cd96972fe33a5074e8d" => 796346,
                "00000117b7a23bc68daecfe6e8e7d89a5fdbb7fc0cb223990ce12b3cb880a0d4" => 796347,
                "00000174ce77270266f72aa4a1b08590c92fbb1f93f408ea38c73600012c31b3" => 796348,
                "000000b5c1cd6e4c02ce8786ddd08e8bfc1cf7b07fc602b9f52bf2eac5f60097" => 796349,
                "0000023ba69970bfb984a7b0681ab6415b4b9e2a15fc633b39e761817b19be4e" => 796350,
                "0000017e956d2468a731f1793ffc337dd49da9f7307dc345d9a0f2176b0ed523" => 796351,
                "00000037e49382e91bf0d0591a0c135b1af0c4d05e5e6f677a37f3fe0be35801" => 796368,
                "000000489916839f007563c09012c428b36203e315a09f83da5b23cba305ab4e" => 796392,

                "00000229571f907785bf6116d2903bb360c2622b0aa39d6ecace211df7ca784c" => 796416,
                "000000a94bb2572fa24a31f594b9abb89039aca2ea3c04e88030aa1937d10552" => 796440,
                "000001b670fabac393967d5af113c2cead715b272143f5e9f5f9ab8fb46a015c" => 796464,
                "00000213c8d42ad05d3884cbbb49ae4908500f1a9199d74deae6bcf02ddf9977" => 796488,

                "00000202179d87e28fe5ca330b8822167100de2628b9cf14a8c7b5c15faeb4e7" => 796512,
                "0000005c5827f52b58f84f868738a1208a0932c6b83440c7e67c563189787343" => 796536,
                "000001f2a3f4e5fcedddf101140387bbb33c01fbf697df1f7e706c65008f9412" => 796560,
                "0000019636a719f79affdc36356555199d1bca2dd0c48809c2d40436eed3eec7" => 796584,

                "00000067c009d837a76555c5ccde03f8d05e163e0338a243a6e71a420b68e5e2" => 796600,
                "000000d56ebf4944d5faf364d5de41c6b1de6cac5332895b9c32368c7cc52934" => 796608,
                "000000fd5ec57b03ed5636192ddc5551622244365d955ad0dc45740ae0cd3671" => 796609,
                "0000047ac18f04084fa183d685b468e4fda5981f47f1bb8b7ee862b485637ad9" => 796610,
                "000000514633ab4962925c6c03068af63733be19c06c0db0493add7a4ba7b067" => 796611,
                "00000286e9a462e67996cab1efb2921debfdfe6eddb7ce36eb3a9d639d072078" => 796612,
                "0000020544964ff0206e190b120884a81f5d685484965c074cf37a22cf423ffe" => 796613,
                "000000edf90c988776c80f37db7b8964030026863c54b49c8521476bd0d90fbf" => 796614,
                "00000126fb0d17f3f267c6754e1874fe9f3f6712a5b13d4f268d1a3b1ed6016b" => 796615,
                "0000023464a6c0e1dbd933960cb9ca25055570d6e6a16395ca9695561780b144" => 796616,
                "0000013c21c2dc49704656ffc5adfd9c58506ac4c9556391d6f2d3d8db579233" => 796617,
                "000000e9567f5ca516947a751e852fc5ce0cf99fb77fdcbe4f6e251d07d8c909" => 796618,
                "0000010a0790fac5c89d517416d5733f087e4ca8a4ab6a4b0d8e047c54b2b4db" => 796619,
                "0000024066d3a8843251d28cca87c791f4d641a61260cc0e93d62f9f287bf7cb" => 796620,
                "00000260b7fffcb3cb26e29c8c4ccb08c95551ec8d206432bb011c35ae61623a" => 796621,
                "000001b1e144731cb6730b68114866ec433e5c1231eddb042c5348746a47598f" => 796622,
                "000001feead43ec6a50c4a3e0e3c122d02bf336dd34e38dd552b23c0acfceded" => 796623,
                "0000015758081916f5ed3dbc203031964a8dce3469b6317608aa4377b3a81e97" => 796624,
                "0000004b942f11f5992574611f54f325be27055928cd75be87b50da335a1840d" => 796625,
                "000000e13fb3802b90e254d17020b84494c4a323f015978d1e65cd46d3f924c7" => 796626,
                "0000004f2d73a3808bebc0f235c4a5ffc6618767f05fabab4ea448f7fc4a88af" => 796627,
                "00000165dc64c1dc0c59dfc1a26c87e7ab5078802069bb1840a4504eebf06c35" => 796628,
                "0000017dfe80c5bdbfd5d854e1f888911addced8219147d8051244dd8112f979" => 796629,
                "000001ed888b4a66feabb13ecb6c6f26ffed26c709df00ce15ce34b8acad2e47" => 796630,
                "000002573d8ac523a0e27883e9f18856c2e272805551605e0e2aca55048b1b78" => 796631,
                "0000003cef7b8e691d58098fc14d4e9a593dd49b5cf6a067cc3165ae99b429f5" => 796632,
                "000001d956c82793ffacf35cafdd343432f345457cf7c424d530685bff800795" => 796633,
                "0000001d70d6f7e26c75c9b5847c0fae6aece5740990a109f6c6e97f7c03ab37" => 796634,
                "0000004d1275d791153d924d4ccb30f8ff847b191e643146d6fd7e76a85f07c5" => 796635,
                "000001b6e08ddc4a60699ff267224de922fdaf4e5a77ca188ca95ef2c8f2bbf8" => 796636,
                "000000e079ce7dcff9674b6ef9c26c2f7d0b577a7df6230da5ebc9f667facbd2" => 796637,
                "000000a23715c758af5ace087f66a2686eba2648601682ebc6a57e9a578f6286" => 796638,
                "000000a1bdc625fab2efc90dfbfc30f2b88be538e88c8993015ab5416e6e8bf7" => 796639,
                "00000022fbc8960a335c090124b1bcb66e539fa5d67a72c0ab58152e60f018c8" => 796656,
                "0000015b85b95ffa0528a2fffbc5938bad0a70ef870a6b16775077030f9d7317" => 796680,

                "0000021715c8575620382ceee42cc7556bac5ed395eaf9c75e2119aa2876a1e0" => 796713,
                _ => u32::MAX,
            },
            _ => u32::MAX,
        }
    }

    pub fn merkle_root_for(chain: ChainType, key: &str) -> UInt256 {
        UInt256::from_hex(match chain {
            ChainType::TestNet => match key {
                "0000021715c8575620382ceee42cc7556bac5ed395eaf9c75e2119aa2876a1e0" => "cbdfce066c9bc3e3683fbcd942f2f444710ada2733bff1c7901acb38e9765361",
                "00000067c009d837a76555c5ccde03f8d05e163e0338a243a6e71a420b68e5e2" => "45f83b09f14b1c71f5f6e19ea2586b49b98a21a62248660d949bcd10aefa3b3d",
                "000003b03c38daf45ec2dea558ac2faac07945abdfe172a23ead6ec3594f96b0" => "ace71208b50f155c9180fd0afd418ad3062baa41f2bbe66ecb797de7b91be651",
                "000000628ef83a2ddf93736e802835f515adea6c81e9bdecbf4d67416ad19f35" => "bdba2c28f9e52cf4dda624b8ae3d03978436fc3a266060b395ab9c2fcc74e507",
                "0000021c387334151438c59551967d61eb68788a5327ce15b39238933d8fa366" => "1c234276d6e9aa4da869259ade20971a6f058510fcae4d344e227d78a9a78c45",
                _ => "0000000000000000000000000000000000000000000000000000000000000000",
// "                _ => "0000000000000000000000000000000000000000000000000000000000000000",
            },
            _ => "0000000000000000000000000000000000000000000000000000000000000000",
        }).unwrap()

    }

    pub fn get_file_as_byte_vec(filename: &String) -> Vec<u8> {
        println!("get_file_as_byte_vec: {}", filename);
        let mut f = fs::File::open(&filename).expect("no file found");
        let metadata = fs::metadata(&filename).expect("unable to read metadata");
        let mut buffer = vec![0; metadata.len() as usize];
        f.read(&mut buffer).expect("buffer overflow");
        buffer
    }

    pub fn message_from_file(name: String) -> Vec<u8> {
        let executable = env::current_exe().unwrap();
        let path = match executable.parent() {
            Some(name) => name,
            _ => panic!(),
        };
        let filepath = format!("{}/../../../files/{}", path.display(), name.as_str());
        println!("{:?}", filepath);
        let file = get_file_as_byte_vec(&filepath);
        file
    }

    pub fn assert_diff_result(chain: ChainType, result: types::MNListDiffResult) {
        let mut masternode_list = unsafe { (*result.masternode_list).decode() };
        let bh = block_height_for(
            chain,
            masternode_list.block_hash.reversed().to_string().as_str(),
        );

        assert!(
            result.has_found_coinbase,
            "Did not find coinbase at height {}",
            bh
        );
        //turned off on purpose as we don't have the coinbase block
        //assert!(result.has_valid_coinbase, "Coinbase not valid at height {}", bh);
        assert!(
            result.has_valid_mn_list_root,
            "rootMNListValid not valid at height {}",
            bh
        );
        assert!(
            result.has_valid_llmq_list_root,
            "rootQuorumListValid not valid at height {}",
            bh
        );
        assert!(
            result.has_valid_quorums,
            "validQuorums not valid at height {}",
            bh
        );
    }

    pub unsafe extern "C" fn block_height_lookup_default(
        block_hash: *mut [u8; 32],
        context: *const std::ffi::c_void,
    ) -> u32 {
        let block_hash = UInt256(*block_hash);
        let data: &mut FFIContext = &mut *(context as *mut FFIContext);
        let hash_reversed = block_hash.clone().reversed().0.to_hex();
        // let height = block_height_for(data.chain, hash_reversed.as_str());
        let height = block_height_for(data.chain, block_hash.0.to_hex().as_str());
        println!("block_height_lookup_default {}: {} ({})", height, hash_reversed, block_hash);
        height
    }

    pub unsafe extern "C" fn block_height_lookup_5078(
        _block_hash: *mut [u8; 32],
        _context: *const std::ffi::c_void,
    ) -> u32 {
        5078
    }
    pub unsafe extern "C" fn block_height_lookup_122088(
        _block_hash: *mut [u8; 32],
        _context: *const std::ffi::c_void,
    ) -> u32 {
        122088
    }
    pub unsafe extern "C" fn get_block_hash_by_height_default(
        _block_height: u32,
        _context: *const std::ffi::c_void,
    ) -> *mut u8 {
        null_mut()
    }

    pub unsafe extern "C" fn get_llmq_snapshot_by_block_height_default(
        _block_height: u32,
        _context: *const std::ffi::c_void,
    ) -> *mut types::LLMQSnapshot {
        null_mut()
    }

    pub unsafe extern "C" fn get_llmq_snapshot_by_block_hash_default(
        _block_hash: *mut [u8; 32],
        _context: *const std::ffi::c_void,
    ) -> *mut types::LLMQSnapshot {
        null_mut()
    }

    pub unsafe extern "C" fn get_masternode_list_by_block_hash_default(
        _block_hash: *mut [u8; 32],
        _context: *const std::ffi::c_void,
    ) -> *mut types::MasternodeList {
        null_mut()
    }

    pub unsafe extern "C" fn get_masternode_list_by_block_hash_from_cache(
        block_hash: *mut [u8; 32],
        context: *const std::ffi::c_void,
    ) -> *mut types::MasternodeList {
        let h = UInt256(*(block_hash));
        let data: &mut FFIContext = &mut *(context as *mut FFIContext);
        if let Some(list) = data.cache.mn_lists.get(&h) {
            println!("get_masternode_list_by_block_hash_from_cache: {}: masternodes: {} quorums: {} mn_merkle_root: {:?}, llmq_merkle_root: {:?}", h, list.masternodes.len(), list.quorums.len(), list.masternode_merkle_root, list.llmq_merkle_root);
            let encoded = list.encode();
            boxed(encoded)
            // &encoded as *const types::MasternodeList
        } else {
            null_mut()
        }
    }

    pub unsafe extern "C" fn masternode_list_save_default(
        _block_hash: *mut [u8; 32],
        _masternode_list: *mut types::MasternodeList,
        _context: *const std::ffi::c_void,
    ) -> bool {
        true
    }
    pub unsafe extern "C" fn masternode_list_save_in_cache(
        block_hash: *mut [u8; 32],
        masternode_list: *mut types::MasternodeList,
        context: *const std::ffi::c_void,
    ) -> bool {
        let h = UInt256(*(block_hash));
        let data: &mut FFIContext = &mut *(context as *mut FFIContext);
        let masternode_list = *masternode_list;
        let masternode_list_decoded = masternode_list.decode();
        println!("masternode_list_save_in_cache: {}", h);
        data.cache.mn_lists.insert(h, masternode_list_decoded);
        true
    }

    pub unsafe extern "C" fn masternode_list_destroy_default(
        _masternode_list: *mut types::MasternodeList,
    ) {
    }
    pub unsafe extern "C" fn hash_destroy_default(_hash: *mut u8) {}

    pub unsafe extern "C" fn should_process_diff_with_range_default(
        base_block_hash: *mut [u8; 32],
        block_hash: *mut [u8; 32],
        context: *const std::ffi::c_void,
    ) -> u8 {
        ProcessingError::None.into()
    }
    pub unsafe extern "C" fn snapshot_destroy_default(_snapshot: *mut types::LLMQSnapshot) {}
    pub unsafe extern "C" fn add_insight_lookup_default(
        _hash: *mut [u8; 32],
        _context: *const std::ffi::c_void,
    ) {
    }
    pub unsafe extern "C" fn save_llmq_snapshot_default(
        block_hash: *mut [u8; 32],
        snapshot: *mut types::LLMQSnapshot,
        _context: *const std::ffi::c_void,
    ) -> bool {
        true
    }
    pub unsafe extern "C" fn save_llmq_snapshot_in_cache(
        block_hash: *mut [u8; 32],
        snapshot: *mut types::LLMQSnapshot,
        context: *const std::ffi::c_void,
    ) -> bool {
        let h = UInt256(*(block_hash));
        let data: &mut FFIContext = &mut *(context as *mut FFIContext);
        let snapshot = *snapshot;
        let snapshot_decoded = snapshot.decode();
        println!("save_llmq_snapshot_in_cache: {}: {:?}", h, snapshot_decoded);
        data.cache.llmq_snapshots.insert(h, snapshot_decoded);
        true
    }

    pub unsafe extern "C" fn log_default(
        message: *const libc::c_char,
        _context: *const std::ffi::c_void,
    ) {
        let c_str = std::ffi::CStr::from_ptr(message);
        println!("{:?}", c_str.to_str().unwrap());
    }

    pub unsafe extern "C" fn get_merkle_root_by_hash_default(
        block_hash: *mut [u8; 32],
        context: *const std::ffi::c_void,
    ) -> *mut u8 {
        let block_hash = UInt256(*block_hash);
        let data: &mut FFIContext = &mut *(context as *mut FFIContext);
        let hash_reversed = block_hash.clone().reversed().0.to_hex();
        let mut hash = merkle_root_for(data.chain, block_hash.0.to_hex().as_str());
        println!("get_merkle_root_by_hash_default {} ({}) => ({})", block_hash, hash_reversed, hash);
        hash.0.as_mut_ptr()
    }

    pub unsafe extern "C" fn should_process_llmq_of_type(
        llmq_type: u8,
        context: *const std::ffi::c_void,
    ) -> bool {
        let data: &mut FFIContext = &mut *(context as *mut FFIContext);

        let quorum_type: u8 = match data.chain {
            ChainType::MainNet => LLMQType::Llmqtype400_60.into(),
            ChainType::TestNet => LLMQType::Llmqtype50_60.into(),
            ChainType::DevNet => LLMQType::Llmqtype60_75.into(),
        };
        llmq_type == quorum_type
    }
    pub unsafe extern "C" fn validate_llmq_callback(
        data: *mut types::LLMQValidationData,
        _context: *const std::ffi::c_void,
    ) -> bool {
        let result = unbox_any(data);
        let types::LLMQValidationData {
            items,
            count,
            commitment_hash,
            all_commitment_aggregated_signature,
            threshold_signature,
            public_key,
        } = *result;
        println!(
            "validate_quorum_callback: {:?}, {}, {:?}, {:?}, {:?}, {:?}",
            items,
            count,
            commitment_hash,
            all_commitment_aggregated_signature,
            threshold_signature,
            public_key
        );

        // bool allCommitmentAggregatedSignatureValidated = [DSBLSKey verifySecureAggregated:commitmentHash signature:allCommitmentAggregatedSignature withPublicKeys:publicKeyArray];

        // let mut inputs = Vec::new();
        // let mut asig = AggregateSignature::new();
        let all_commitment_aggregated_signature = UInt768(*all_commitment_aggregated_signature);
        let threshold_signature = UInt768(*threshold_signature);
        let public_key = UInt384(*public_key);
        let commitment_hash = UInt256(*commitment_hash);

        let infos = (0..count)
            .into_iter()
            .map(|i| AggregationInfo {
                public_key: UInt384(*(*(items.offset(i as isize)))),
                digest: commitment_hash,
            })
            .collect::<Vec<AggregationInfo>>();

        true
    }

    pub fn perform_mnlist_diff_test_for_message(
        hex_string: &str,
        should_be_total_transactions: u32,
        verify_string_hashes: Vec<&str>,
        verify_string_smle_hashes: Vec<&str>,
    ) {
        println!("perform_mnlist_diff_test_for_message...");
        let bytes = Vec::from_hex(&hex_string).unwrap();
        let length = bytes.len();
        let c_array = bytes.as_ptr();
        let message: &[u8] = unsafe { slice::from_raw_parts(c_array, length) };
        let chain = ChainType::TestNet;
        let offset = &mut 0;
        assert!(length - *offset >= 32);
        let base_block_hash = UInt256::from_bytes(message, offset).unwrap();
        assert_ne!(
            base_block_hash,
            UInt256::default(), /*UINT256_ZERO*/
            "Base block hash should NOT be empty here"
        );
        assert!(length - *offset >= 32);
        let _block_hash = UInt256::from_bytes(message, offset).unwrap();
        assert!(length - *offset >= 4);
        let total_transactions = u32::from_bytes(message, offset).unwrap();
        assert_eq!(
            total_transactions, should_be_total_transactions,
            "Invalid transaction count"
        );
        let use_insight_as_backup = false;
        let base_masternode_list_hash: *const u8 = null_mut();
        let context = &mut FFIContext {
            chain,
            cache: MasternodeProcessorCache::default(),
        } as *mut _ as *mut std::ffi::c_void;

        let cache = unsafe { processor_create_cache() };
        let processor = unsafe {
            register_processor(
                get_merkle_root_by_hash_default,
                block_height_lookup_122088,
                get_block_hash_by_height_default,
                get_llmq_snapshot_by_block_hash_default,
                save_llmq_snapshot_default,
                get_masternode_list_by_block_hash_default,
                masternode_list_save_default,
                masternode_list_destroy_default,
                add_insight_lookup_default,
                should_process_llmq_of_type,
                validate_llmq_callback,
                hash_destroy_default,
                snapshot_destroy_default,
                should_process_diff_with_range_default,
                log_default,
            )
        };

        let result = process_mnlistdiff_from_message(
            c_array,
            length,
            use_insight_as_backup,
            false,
            chain.genesis_hash().0.as_ptr(),
            processor,
            cache,
            context,
        );
        println!("result: {:?}", result);
        let result = unsafe { unbox_any(result) };
        let masternode_list = unsafe { (*unbox_any(result.masternode_list)).decode() };
        let masternodes = masternode_list.masternodes.clone();
        let mut pro_tx_hashes: Vec<UInt256> = masternodes.clone().into_keys().collect();
        pro_tx_hashes.sort();
        let mut verify_hashes: Vec<UInt256> = verify_string_hashes
            .into_iter()
            .map(|h| {
                Vec::from_hex(h)
                    .unwrap()
                    .read_with::<UInt256>(&mut 0, byte::LE)
                    .unwrap()
                    .reversed()
            })
            .collect();
        verify_hashes.sort();
        assert_eq!(verify_hashes, pro_tx_hashes, "Provider transaction hashes");
        let mut masternode_list_hashes: Vec<UInt256> = pro_tx_hashes
            .clone()
            .iter()
            .map(|hash| masternodes[hash].entry_hash)
            .collect();
        masternode_list_hashes.sort();
        let mut verify_smle_hashes: Vec<UInt256> = verify_string_smle_hashes
            .into_iter()
            .map(|h| {
                Vec::from_hex(h)
                    .unwrap()
                    .read_with::<UInt256>(&mut 0, byte::LE)
                    .unwrap()
            })
            .collect();
        verify_smle_hashes.sort();
        assert_eq!(
            masternode_list_hashes, verify_smle_hashes,
            "SMLE transaction hashes"
        );
        assert!(
            result.has_found_coinbase,
            "The coinbase was not part of provided hashes"
        );
    }
}
