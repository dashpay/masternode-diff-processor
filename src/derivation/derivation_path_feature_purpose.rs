use crate::crypto::UInt256;

pub enum DerivationPathFeaturePurpose {
    Default = 9,
    Identities = 5,
    IdentitiesSubfeatureAuthentication = 0,
    IdentitiesSubfeatureRegistration = 1,
    IdentitiesSubfeatureTopup = 2,
    IdentitiesSubfeatureInvitations = 3,
    DashPay = 15,
}

impl From<u32> for DerivationPathFeaturePurpose {
    fn from(orig: u32) -> Self {
        match orig {
            0 => DerivationPathFeaturePurpose::IdentitiesSubfeatureAuthentication,
            1 => DerivationPathFeaturePurpose::IdentitiesSubfeatureRegistration,
            2 => DerivationPathFeaturePurpose::IdentitiesSubfeatureTopup,
            3 => DerivationPathFeaturePurpose::IdentitiesSubfeatureInvitations,
            5 => DerivationPathFeaturePurpose::Identities,
            9 => DerivationPathFeaturePurpose::Default,
            15 => DerivationPathFeaturePurpose::DashPay,
            _ => DerivationPathFeaturePurpose::Default,
        }
    }
}

impl From<DerivationPathFeaturePurpose> for u32 {
    fn from(value: DerivationPathFeaturePurpose) -> Self {
        match value {
            DerivationPathFeaturePurpose::Default => 9,
            DerivationPathFeaturePurpose::Identities => 5,
            DerivationPathFeaturePurpose::IdentitiesSubfeatureAuthentication => 0,
            DerivationPathFeaturePurpose::IdentitiesSubfeatureRegistration => 1,
            DerivationPathFeaturePurpose::IdentitiesSubfeatureTopup => 2,
            DerivationPathFeaturePurpose::IdentitiesSubfeatureInvitations => 3,
            DerivationPathFeaturePurpose::DashPay => 15,
        }
    }
}

impl From<DerivationPathFeaturePurpose> for UInt256 {
    fn from(value: DerivationPathFeaturePurpose) -> Self {
        match value {
            DerivationPathFeaturePurpose::Default => UInt256::from(9u32),
            DerivationPathFeaturePurpose::Identities => UInt256::from(5u32),
            DerivationPathFeaturePurpose::IdentitiesSubfeatureAuthentication => UInt256::MIN,
            DerivationPathFeaturePurpose::IdentitiesSubfeatureRegistration => UInt256::from(1u32),
            DerivationPathFeaturePurpose::IdentitiesSubfeatureTopup => UInt256::from(2u32),
            DerivationPathFeaturePurpose::IdentitiesSubfeatureInvitations => UInt256::from(3u32),
            DerivationPathFeaturePurpose::DashPay => UInt256::from(15u32),
        }
    }
}

impl DerivationPathFeaturePurpose {
    pub fn into_u32(self) -> u32 {
        self.into()
    }
    pub fn into_u256(self) -> UInt256 {
        self.into()
    }
}
