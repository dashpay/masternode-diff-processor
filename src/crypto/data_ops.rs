// use std::convert::TryInto;
use std::collections::HashSet;
use std::hash::Hash;



/// Extracts the common values in `a` and `b` into a new set.
pub fn inplace_intersection<T>(a: &mut HashSet<T>, b: &mut HashSet<T>) -> HashSet<T>
    where
        T: Hash,
        T: Eq,
{
    let x: HashSet<(T, bool)> = a
        .drain()
        .map(|v| {
            let intersects = b.contains(&v);
            (v, intersects)
        })
        .collect();
    let mut c = HashSet::new();
    for (v, is_inter) in x {
        if is_inter {
            c.insert(v);
        } else {
            a.insert(v);
        }
    }
    b.retain(|v| !c.contains(&v));
    c
}

// pub fn sha256_1(data: &[u8]) -> [u8; 32] {
//     let mut hasher = Sha256::new();
//     hasher.update(data);
//     let result = hasher.finalize();
//     result.try_into().expect("error sha-256")
// }
//
// pub fn sha256_2(data: &[u8]) -> [u8; 32] {
//     let mut hasher = Sha256::new();
//     hasher.update(data);
//     let result = hasher.finalize();
//     hasher.update(&result);
//     hasher.finalize().try_into().expect("error double sha-256")
// }

/*pub fn script_elements(script: &[u8]) -> &[u8] {
    // NSMutableArray *a = [NSMutableArray array];
    let mut a = [0u8];

    //const uint8_t *b = (const uint8_t *)self.bytes;
    let mut l = 0;
    let length = script.len();

    for mut i in 0..length {
        if script[i] > OP_PUSHDATA4.into_u8() {
            l = 1;
            a.push(b[i]);
        }
        match b[i] {
            0 => {
                l = 1;
                a.push(0);
                continue;
            },
            OP_PUSHDATA1 => {
                i += 1;
                if i + 1 > length { return &a; }
                l = b[i];
                i += 1;
                break;
            },
            OP_PUSHDATA2 => {
                i += 1;
                if i + 2 > length { return &a; }
                l = b[i];
                i += 2;
                break;
            },
            OP_PUSHDATA4 => {
                i += 1;
                if i + 4 > length { return &a; }
                l = b[i];
                i += 4;
                break;
            }
            _ => {
                l = b[i];
                i += 1;
                break;
            }
        }
        if i + l > length { return &a; }
        [a addObject:[NSData dataWithBytes:&b[i] length:l]];
    }
    return &a;
}

pub fn address_with_script_pub_key(script: &[u8], pub_key_address: u8, script_address: i32) -> &str {
    let elem = script_elements(script);
    let l = elem.len();
    let mut d: Vec<u8> = Vec::new();

    if l == 5 &&
        elem[0] == OP_DUP &&
        elem[1] == OP_HASH160 &&
        elem[2] == 20 &&
        elem[3] == OP_EQUALVERIFY &&
        elem[4] == OP_CHECKSIG {
        // pay-to-pubkey-hash scriptPubKey
        d.push(pub_key_address);
        d.push(20);
    } else if l == 3 &&
        elem[0] == OP_HASH160 &&
        elem[1] == 20 &&
        elem[2] == OP_EQUAL {
        // pay-to-script-hash scriptPubKey
        d.push(script_address as u8);
        d.push(20);
    } else if l == 2 &&
        elem[0] == 65 ||
        elem[0] == 33 &&
        elem[1] == OP_CHECKSIG {
        // pay-to-pubkey scriptPubKey
        d.push(pub_key_address);
        d.push(elem[0].hash)
    } else {
        // unknown script type
        //return None;
    }
    d.base_58_check()
}

pub fn address_with_script_signature(signature: &[u8], pub_key_address: u8, script_address: i32) -> &str {
    let elem = script_elements(script);
    let l = elem.len();
    let mut d: Vec<u8> = Vec::new();
    if l >= 2 &&
        elem[l - 2] <= OP_PUSHDATA4.into_u8() &&
        elem[l - 2] > 0 &&
        (elem[l - 1] == 65 ||
        elem[l - 1] == 33) {
        // pay-to-pubkey-hash scriptSig
        d.push(pub_key_address);
        d.push(elem[l - 1].has);
        hash160::Hash::hash(&self.key.serialize())
    } else if l >= 2 &&
        elem[l - 2] <= OP_PUSHDATA4.into_u8() &&
        elem[l - 2] > 0 &&
        elem[l - 1] <= OP_PUSHDATA4.into_u8() &&
        elem[l - 1] > 0 {
        d.push(script_address as u8)
        //[d appendBytes:[elem[l - 1] hash160].u8 length:sizeof(UInt160)];

    } else if l >= 1 && elem[l - 1] <= OP_PUSHDATA4.into_u8() && elem[l - 1] > 0 {
        // pay-to-pubkey scriptSig
        d.push(pub_key_address);
        //        DSKey * key = [DSKey keyRecoveredFromCompactSig:elem[l - 1] andMessageDigest:transactionHash];
        //        [d appendBytes:[key.publicKey hash160].u8 length:sizeof(UInt160)];
        //TODO: implement Peter Wullie's pubKey recovery from signature
        //return None;
    }

    else {
        // unknown script type
        //return None;
    }
    d.base_58_check()
}*/
