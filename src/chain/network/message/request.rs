use std::time::SystemTime;
use crate::consensus::Encodable;
use crate::consensus::encode::VarInt;
use crate::crypto::{UInt128, UInt256};
use crate::crypto::byte_util::Zeroable;
use crate::chain::network::message::inv_type::InvType;
use crate::chain::network::message::r#type::Type;
use crate::chain::network::net_address::NetAddress;
use crate::chain::network::peer::{ENABLED_SERVICES, LOCAL_HOST};
use crate::crypto::UTXO;
use crate::util::time::TimeUtil;

pub trait IRequest {
    fn r#type(&self) -> Type;
    fn to_data(self) -> Vec<u8>;
}

// #[derive(Debug, Default)]
// pub enum GovernanceSyncRequest {
//     Objects(Request),
//     Votes(Request)
// }

// impl GovernanceSyncRequest {
    // pub fn state(&self) -> GovernanceRequestState {
    //     match self {
    //         GovernanceSyncRequest::Objects(_, state) => state,
    //         GovernanceSyncRequest::Votes(_, state) => state,
    //         // _ => panic!("wrong governance sync request")
    //     }
    // }
    //
    // pub fn request(&self) -> Request {
    //     match self {
    //         GovernanceSyncRequest::Objects(request, _) => request,
    //         GovernanceSyncRequest::Votes(request, _) => request,
    //         // _ => panic!("wrong governance sync request")
    //     }
    // }
// }

// pub enum GovernanceHashesRequest {
//     Object(Request, GovernanceRequestState),
//     Vote(Request, GovernanceRequestState)
// }
//
// impl GovernanceHashesRequest {
//     pub fn request(&self) -> Request {
//         match self {
//             GovernanceHashesRequest::Objects(&request, _) |
//             GovernanceHashesRequest::Votes(&request, _) => request
//         }
//     }
// }

pub enum Request {
    Addr,
    FilterLoad(Vec<u8>),
    GetBlocks(Vec<UInt256>, UInt256, u32),
    GetHeaders(Vec<UInt256>, UInt256, u32),
    Inv(InvType, Vec<UInt256>),
    NotFound(Vec<u8>),
    Ping(u64),
    Version(UInt128, u16, u32, u64, u16, u64, String),
    GovernanceHashes(InvType, Vec<UInt256>),
    GovernanceSync(UInt256, Vec<u8>),
    GovernanceSyncObjects,
    GovernanceSyncVotes,
    DSeg(UTXO),
    GetMNListDiff(UInt256, UInt256),
    GetQRInfo(Vec<UInt256>, UInt256, bool),
    GetDataForTransactionHash(UInt256),
    GetDataForTransactionHashes(Option<Vec<UInt256>>, Option<Vec<UInt256>>, Option<Vec<UInt256>>, Option<Vec<UInt256>>, Option<Vec<UInt256>>),
    TransactionInv(Vec<UInt256>, Vec<UInt256>),
    Default(Type),
}

fn array_of_hashes_enc(hashes: &Vec<UInt256>, inv_type: InvType, s: &mut Vec<u8>) {
    // if let Some(hashes) = hashes {
        let inv_type_clone = inv_type.clone(); // Create a clone of the reference
        let inv: u32 = inv_type_clone.into();
        let mut buf = Vec::<u8>::new();
        hashes.iter().for_each(|hash| {
            inv.enc(&mut buf); // Use the clone in the closure
            hash.enc(&mut buf);
        });
        s.extend(buf);
    // }

}

impl IRequest for Request {
    fn r#type(&self) -> Type {
        match self {
            Request::Addr => Type::Addr,
            Request::FilterLoad(..) => Type::Filterload,
            Request::GetBlocks(..) => Type::Getblocks,
            Request::GetHeaders(..) => Type::Getheaders,
            Request::Inv(..) |
            Request::TransactionInv(..) => Type::Inv,
            Request::NotFound(..) => Type::NotFound,
            Request::Ping(..) => Type::Ping,
            Request::Version(..) => Type::Version,
            Request::GovernanceHashes(..) |
            Request::GetDataForTransactionHash(..) |
            Request::GetDataForTransactionHashes(..) => Type::Getdata,
            Request::GovernanceSync(..) => Type::Govsync,
            Request::DSeg(..) => Type::Dseg,
            Request::GetMNListDiff(..) => Type::Getmnlistd,
            Request::GetQRInfo(..) => Type::Getqrinfo,
            Request::Default(r#type) => r#type.clone(),
            Request::GovernanceSyncObjects => Type::Govsync,
            Request::GovernanceSyncVotes => Type::Govobjvote,
        }
    }

    fn to_data(self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();
        match self {
            Request::Default(..) => {},
            Request::Addr => {
                // TODO: send peer addresses we know about
                VarInt(0).enc(&mut buffer);
            },
            Request::FilterLoad(data) => {
                data.enc(&mut buffer);
            },
            Request::GetBlocks(locators, hash_stop, protocol_version) |
            Request::GetHeaders(locators, hash_stop, protocol_version) => {
                protocol_version.enc(&mut buffer);
                VarInt(locators.len() as u64).enc(&mut buffer);
                locators.iter().for_each(|locator| {
                    locator.enc(&mut buffer);
                });
                hash_stop.enc(&mut buffer);
            },
            Request::NotFound(data) => {
                VarInt((data.len() / 36) as u64).enc(&mut buffer);
                data.enc(&mut buffer);
            },
            Request::Ping(local_nonce) => {
                local_nonce.enc(&mut buffer);
            },
            Request::Version(address, port, protocol_version, services, standard_port, local_nonce, useragent) => {
                protocol_version.enc(&mut buffer);
                ENABLED_SERVICES.enc(&mut buffer);
                SystemTime::seconds_since_1970().enc(&mut buffer);
                services.enc(&mut buffer);
                address.enc(&mut buffer);
                port.swap_bytes().enc(&mut buffer);
                NetAddress::new(LOCAL_HOST, standard_port, ENABLED_SERVICES).enc(&mut buffer);
                local_nonce.enc(&mut buffer);
                useragent.enc(&mut buffer);
                0u32.enc(&mut buffer); // last block received
                0u8.enc(&mut buffer); // relay transactions (no for SPV bloom filter mode)
            },
            Request::GovernanceSync(parent_hash, filter_data) => {
                parent_hash.enc(&mut buffer);
                filter_data.enc(&mut buffer);
            },
            Request::Inv(inv_type, hashes) |
            Request::GovernanceHashes(inv_type, hashes) => {
                VarInt(hashes.len() as u64).enc(&mut buffer);
                array_of_hashes_enc(&hashes, inv_type, &mut buffer);
            },
            Request::DSeg(utxo) => {
                utxo.hash.enc(&mut buffer);
                if utxo.hash.is_zero() {
                    u32::MAX.enc(&mut buffer);
                } else {
                    utxo.n.enc(&mut buffer);
                }
                0u8.enc(&mut buffer);
                u32::MAX.enc(&mut buffer);
            },
            Request::GetMNListDiff(base_block_hash, block_hash) => {
                base_block_hash.enc(&mut buffer);
                block_hash.enc(&mut buffer);
            },
            Request::GetQRInfo(base_block_hashes, block_hash, extra_share) => {
                // Number of masternode lists the light client knows
                VarInt(base_block_hashes.len() as u64).enc(&mut buffer);
                // The base block hashes of the masternode lists the light client knows
                base_block_hashes.iter().for_each(|hash| {
                    hash.enc(&mut buffer);
                });
                // Hash of the height the client requests
                block_hash.enc(&mut buffer);
                // Flag to indicate if an extra share is requested
                if extra_share { 1u8 } else { 0u8 }.enc(&mut buffer);
            },
            Request::GetDataForTransactionHash(tx_hash) => {
                VarInt(1u64).enc(&mut buffer);
                let tx_type: u32 = InvType::Tx.into();
                tx_type.enc(&mut buffer);
                tx_hash.enc(&mut buffer);
            },
            Request::GetDataForTransactionHashes(tx_hashes, block_hashes, is_lock_hashes, isd_lock_hashes, c_lock_hashes) => {
                let tx_hashes = tx_hashes.unwrap_or(vec![]);
                let block_hashes = block_hashes.unwrap_or(vec![]);
                let is_lock_hashes = is_lock_hashes.unwrap_or(vec![]);
                let isd_lock_hashes = isd_lock_hashes.unwrap_or(vec![]);
                let c_lock_hashes = c_lock_hashes.unwrap_or(vec![]);
                let size = tx_hashes.len() + block_hashes.len() + is_lock_hashes.len() + isd_lock_hashes.len() + c_lock_hashes.len();
                VarInt(size as u64).enc(&mut buffer);
                array_of_hashes_enc(&tx_hashes, InvType::Tx, &mut buffer);
                array_of_hashes_enc(&is_lock_hashes, InvType::InstantSendLock, &mut buffer);
                array_of_hashes_enc(&isd_lock_hashes, InvType::InstantSendDeterministicLock, &mut buffer);
                array_of_hashes_enc(&block_hashes, InvType::Merkleblock, &mut buffer);
                array_of_hashes_enc(&c_lock_hashes, InvType::ChainLockSignature, &mut buffer);
            },
            Request::TransactionInv(tx_hashes, tx_lock_request_hashes) => {
                let tx_hashes_len = tx_hashes.len();
                let tx_lock_request_hashes_len = tx_lock_request_hashes.len();
                let size = tx_hashes_len + tx_lock_request_hashes_len;
                VarInt(size as u64).enc(&mut buffer);
                array_of_hashes_enc(&tx_hashes, InvType::Tx, &mut buffer);
                array_of_hashes_enc(&tx_lock_request_hashes, InvType::TxLockRequest, &mut buffer);
            },
            Request::GovernanceSyncObjects |
            Request::GovernanceSyncVotes => {},
        }
        buffer
    }
}
