use byte::ctx::{Endian, NULL, Str};
use byte::{BytesExt, TryRead};

#[derive(Clone, Debug, Default, PartialEq)]
pub enum Type {
    #[default]
    WrongType,
    Version,
    Verack,
    Addr,
    Inv,
    Getdata,
    NotFound,
    Getblocks,
    Getheaders,
    Tx,
    Ix, // deprecated in version 14
    Txlvote, // deprecated in version 14
    Islock, // version 14
    Isdlock, // version 14
    Block,
    Chainlock,
    Headers,
    Getaddr,
    Mempool,
    Ping,
    Pong,
    Filterload,
    Filteradd,
    Filterclear,
    Merkleblock,
    Alert,
    Reject, // BIP61: https://github.com/bitcoin/bips/blob/master/bip-0061.mediawiki
    Sendheaders, // BIP130: https://github.com/bitcoin/bips/blob/master/bip-0130.mediawiki
    Feefilter, // BIP133: https://github.com/bitcoin/bips/blob/master/bip-0133.mediawiki
    Senddsq, // version 14
    Sendcmpct, // version 12.3
    Sendaddrv2, // version 12.3

    //Dash specific
    //Control
    Spork,
    GetSporks,

    //Masternode
    Dseg,
    Mnb,
    Mnget,
    Mnp,
    Mnv,
    Mnw,
    Mnwb,
    Ssc,
    Getmnlistd,
    Mnlistdiff,
    Qrinfo,
    Getqrinfo,
    //Governance
    Govobj,
    Govobjvote,
    Govsync,
    //Private send
    DarkSendAnnounce,
    DarkSendControl,
    DarkSendFinish,
    DarkSendInitiate,
    DarkSendQuorum,
    DarkSendSession,
    DarkSendSessionUpdate,
    DarkSendTX,
}

// Regex
// (Type::[A-Za-z]+) => (\"[A-Za-z]+\")
// $2 => $1
impl From<&str> for Type {
    fn from(orig: &str) -> Self {
        match orig {
            "version" => Type::Version,
            "verack" => Type::Verack,
            "addr" => Type::Addr,
            "inv" => Type::Inv,
            "getdata" => Type::Getdata,
            "notfound" => Type::NotFound,
            "getblocks" => Type::Getblocks,
            "getheaders" => Type::Getheaders,
            "tx" => Type::Tx,
            "ix" => Type::Ix,
            "txlvote" => Type::Txlvote,
            "islock" => Type::Islock,
            "isdlock" => Type::Isdlock,
            "block" => Type::Block,
            "clsig" => Type::Chainlock,
            "headers" => Type::Headers,
            "getaddr" => Type::Getaddr,
            "mempool" => Type::Mempool,
            "ping" => Type::Ping,
            "pong" => Type::Pong,
            "filterload" => Type::Filterload,
            "filteradd" => Type::Filteradd,
            "filterclear" => Type::Filterclear,
            "merkleblock" => Type::Merkleblock,
            "alert" => Type::Alert,
            "reject" => Type::Reject,
            "sendheaders" => Type::Sendheaders,
            "feefilter" => Type::Feefilter,
            "senddsq" => Type::Senddsq,
            "sendcmpct" => Type::Sendcmpct,
            "sendaddrv2" => Type::Sendaddrv2,
            "spork" => Type::Spork,
            "getsporks" => Type::GetSporks,
            "dseg" => Type::Dseg,
            "mnb" => Type::Mnb,
            "mnget" => Type::Mnget,
            "mnp" => Type::Mnp,
            "mnv" => Type::Mnv,
            "mnw" => Type::Mnw,
            "mnwb" => Type::Mnwb,
            "ssc" => Type::Ssc,
            "getmnlistd" => Type::Getmnlistd,
            "mnlistdiff" => Type::Mnlistdiff,
            "qrinfo" => Type::Qrinfo,
            "getqrinfo" => Type::Getqrinfo,
            "govobj" => Type::Govobj,
            "govobjvote" => Type::Govobjvote,
            "govsync" => Type::Govsync,
            "dsa" => Type::DarkSendAnnounce,
            "dsc" => Type::DarkSendControl,
            "dsf" => Type::DarkSendFinish,
            "dsi" => Type::DarkSendInitiate,
            "dsq" => Type::DarkSendQuorum,
            "dss" => Type::DarkSendSession,
            "dssu" => Type::DarkSendSessionUpdate,
            "dstx" => Type::DarkSendTX,

            _ => Type::WrongType
        }
    }
}

impl From<Type> for &str {
    fn from(value: Type) -> Self {
        match value {
            Type::WrongType => "",
            Type::Version => "version",
            Type::Verack => "verack",
            Type::Addr => "addr",
            Type::Inv => "inv",
            Type::Getdata => "getdata",
            Type::NotFound => "notfound",
            Type::Getblocks => "getblocks",
            Type::Getheaders => "getheaders",
            Type::Tx => "tx",
            Type::Ix => "ix",
            Type::Txlvote => "txlvote",
            Type::Islock => "islock",
            Type::Isdlock => "isdlock",
            Type::Block => "block",
            Type::Chainlock => "clsig",
            Type::Headers => "headers",
            Type::Getaddr => "getaddr",
            Type::Mempool => "mempool",
            Type::Ping => "ping",
            Type::Pong => "pong",
            Type::Filterload => "filterload",
            Type::Filteradd => "filteradd",
            Type::Filterclear => "filterclear",
            Type::Merkleblock => "merkleblock",
            Type::Alert => "alert",
            Type::Reject => "reject",
            Type::Sendheaders => "sendheaders",
            Type::Feefilter => "feefilter",
            Type::Senddsq => "senddsq",
            Type::Sendcmpct => "sendcmpct",
            Type::Sendaddrv2 => "sendaddrv2",
            Type::Spork => "spork",
            Type::GetSporks => "getsporks",
            Type::Dseg => "dseg",
            Type::Mnb => "mnb",
            Type::Mnget => "mnget",
            Type::Mnp => "mnp",
            Type::Mnv => "mnv",
            Type::Mnw => "mnw",
            Type::Mnwb => "mnwb",
            Type::Ssc => "ssc",
            Type::Getmnlistd => "getmnlistd",
            Type::Mnlistdiff => "mnlistdiff",
            Type::Qrinfo => "qrinfo",
            Type::Getqrinfo => "getqrinfo",
            Type::Govobj => "govobj",
            Type::Govobjvote => "govobjvote",
            Type::Govsync => "govsync",
            Type::DarkSendAnnounce => "dsa",
            Type::DarkSendControl => "dsc",
            Type::DarkSendFinish => "dsf",
            Type::DarkSendInitiate => "dsi",
            Type::DarkSendQuorum=> "dsq",
            Type::DarkSendSession => "dss",
            Type::DarkSendSessionUpdate => "dssu",
            Type::DarkSendTX => "dstx",
        }
    }
}
impl From<Type> for String {
    fn from(value: Type) -> Self {
        let str: &str = value.into();
        str.to_string()
    }
}

impl<'a> TryRead<'a, Endian> for Type {
    fn try_read(bytes: &'a [u8], _endian: Endian) -> byte::Result<(Self, usize)> {
        let offset: &mut usize = &mut 0;
        let str = bytes.read_with::<&str>(offset, Str::Delimiter(NULL)).unwrap();
        Ok((Type::from(str), *offset))
    }
}
