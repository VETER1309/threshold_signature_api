use libc::c_char;
use std::ffi::{CStr, CString};

use schnorrkel::{
    musig::{
        aggregate_public_key_from_slice, collect_cosignatures, AggregatePublicKey, Commitment,
        Cosignature, Reveal,
    },
    signing_context, Keypair, PublicKey,
};

#[no_mangle]
pub extern "C" fn addition(a: u32, b: u32) -> u32 {
    a + b
}

#[allow(dead_code)]
pub extern "C" fn fix_linking_when_not_using_stdlib() {
    panic!()
}

// TODO: Check if there are some logic problems！！！
// TODO: Test these interfaces！！！
// TODO: Optimize these functions！！！
#[no_mangle]
pub extern "C" fn get_my_commit(bytes: *const c_char) -> *mut c_char {
    let c_str = unsafe {
        assert!(!bytes.is_null());

        CStr::from_ptr(bytes)
    };

    let r_str = c_str.to_str().unwrap();
    let keypair = Keypair::from_half_ed25519_bytes(&hex::decode(r_str).unwrap()[..]).unwrap();
    let t = signing_context(b"multi-sig").bytes(b"We are legion!");
    let musig = keypair.musig(t);
    let commit_hex = hex::encode(&musig.our_commitment().0[..]);
    let c_commit_str = CString::new(commit_hex).unwrap();
    c_commit_str.into_raw()
}

#[no_mangle]
pub extern "C" fn get_my_reveal(
    privkey: *const c_char,
    commits: *const c_char,
    pubkeys: *const c_char,
) -> *mut c_char {
    // construct musig state
    let c_priv = unsafe {
        assert!(!privkey.is_null());

        CStr::from_ptr(privkey)
    };

    let r_priv = c_priv.to_str().unwrap();
    let keypair = Keypair::from_half_ed25519_bytes(&hex::decode(r_priv).unwrap()[..]).unwrap();
    let t = signing_context(b"multi-sig").bytes(b"We are legion!");
    let mut musig = keypair.musig(t);
    // construct the public key of all people
    let c_pubkeys = unsafe {
        assert!(!pubkeys.is_null());

        CStr::from_ptr(pubkeys)
    };

    let r_pubkeys_bytes = c_pubkeys.to_bytes();
    // ensure that it is the correct public key length
    assert!(r_pubkeys_bytes.len() % 32 == 0);
    let pubkeys_num = r_pubkeys_bytes.len() / 32;

    let c_commits = unsafe {
        assert!(!commits.is_null());

        CStr::from_ptr(commits)
    };

    let commits_bytes = c_commits.to_bytes();
    // ensure that it is the correct commit length
    assert!(commits_bytes.len() % 16 == 0);
    let commit_num = commits_bytes.len() / 16;
    // make sure the number of public keys and the number of commits are the same
    assert!(commit_num == pubkeys_num);

    for n in 0..pubkeys_num {
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&commits_bytes[n..n + 16]);
        let commit = Commitment(bytes);
        let publickey = PublicKey::from_bytes(&r_pubkeys_bytes[n..n + 32]).unwrap();
        musig.add_their_commitment(publickey, commit).unwrap();
    }
    let reveal = musig.reveal_stage().our_reveal().to_owned();
    let reveal_hex = hex::encode(reveal.0);
    let c_commit_str = CString::new(reveal_hex).unwrap();
    c_commit_str.into_raw()
}

#[no_mangle]
pub extern "C" fn get_my_cosign(
    privkey: *const c_char,
    reveals: *const c_char,
    pubkeys: *const c_char,
) -> *mut c_char {
    // construct musig state
    let c_priv = unsafe {
        assert!(!privkey.is_null());

        CStr::from_ptr(privkey)
    };

    let r_priv = c_priv.to_str().unwrap();
    let keypair = Keypair::from_half_ed25519_bytes(&hex::decode(r_priv).unwrap()[..]).unwrap();
    let t = signing_context(b"multi-sig").bytes(b"We are legion!");
    // enter the revealing stage
    let mut musig = keypair.musig(t).reveal_stage();
    // construct the public key of all people
    let c_pubkeys = unsafe {
        assert!(!pubkeys.is_null());

        CStr::from_ptr(pubkeys)
    };

    let r_pubkeys_bytes = c_pubkeys.to_bytes();
    // ensure that it is the correct public key length
    assert!(r_pubkeys_bytes.len() % 32 == 0);
    let pubkeys_num = r_pubkeys_bytes.len() / 32;

    let c_reveals = unsafe {
        assert!(!reveals.is_null());

        CStr::from_ptr(reveals)
    };

    let reveals_bytes = c_reveals.to_bytes();
    // ensure that it is the correct reveal length
    assert!(reveals_bytes.len() % 96 == 0);
    let reveals_num = reveals_bytes.len() / 96;
    // make sure the number of public keys and the number of commits are the same
    assert!(reveals_num == pubkeys_num);

    for n in 0..pubkeys_num {
        let mut bytes = [0u8; 96];
        bytes.copy_from_slice(&reveals_bytes[n..n + 96]);
        let reveal = Reveal(bytes);
        let publickey = PublicKey::from_bytes(&r_pubkeys_bytes[n..n + 32]).unwrap();
        musig.add_their_reveal(publickey, reveal).unwrap();
    }
    // get cosign
    let cosign = musig.cosign_stage().our_cosignature().to_owned();
    let cosign_hex = hex::encode(cosign.0);
    let c_cosign_str = CString::new(cosign_hex).unwrap();
    c_cosign_str.into_raw()
}

#[no_mangle]
pub extern "C" fn get_signature(
    reveals: *const c_char,
    pubkeys: *const c_char,
    cosign: *const c_char,
) -> *mut c_char {
    let t = signing_context(b"multi-sig").bytes(b"We are legion!");
    let mut c = collect_cosignatures(t.clone());

    // construct the public key of all people
    let c_pubkeys = unsafe {
        assert!(!pubkeys.is_null());

        CStr::from_ptr(pubkeys)
    };

    let r_pubkeys_bytes = c_pubkeys.to_bytes();
    // ensure that it is the correct public key length
    assert!(r_pubkeys_bytes.len() % 32 == 0);
    let pubkeys_num = r_pubkeys_bytes.len() / 32;

    // construct the cosign of all people
    let c_cosign = unsafe {
        assert!(!cosign.is_null());

        CStr::from_ptr(cosign)
    };

    let r_cosign_bytes = c_cosign.to_bytes();
    // ensure that it is the correct cosign length
    assert!(r_cosign_bytes.len() % 32 == 0);
    let cosign_num = r_cosign_bytes.len() / 32;

    let c_reveals = unsafe {
        assert!(!reveals.is_null());

        CStr::from_ptr(reveals)
    };

    let reveals_bytes = c_reveals.to_bytes();
    // ensure that it is the correct reveal length
    assert!(reveals_bytes.len() % 96 == 0);
    let reveals_num = reveals_bytes.len() / 96;
    // make sure the number of public keys and the number of commits are the same
    assert!(reveals_num == pubkeys_num && cosign_num == pubkeys_num);

    for n in 0..pubkeys_num {
        let mut reveal_bytes = [0u8; 96];
        reveal_bytes.copy_from_slice(&reveals_bytes[n..n + 96]);
        let reveal = Reveal(reveal_bytes);
        let mut cosign_bytes = [0u8; 32];
        cosign_bytes.copy_from_slice(&reveals_bytes[n..n + 32]);
        let cosign = Cosignature(cosign_bytes);

        let publickey = PublicKey::from_bytes(&r_pubkeys_bytes[n..n + 32]).unwrap();

        c.add(publickey, reveal, cosign).unwrap();
    }
    // get cosign
    let sig = c.signature();
    let sig_hex = hex::encode(sig.to_bytes());
    let c_sig_str = CString::new(sig_hex).unwrap();
    c_sig_str.into_raw()
}

#[no_mangle]
pub extern "C" fn get_agg_pubkey(pubkeys: *const c_char) -> *mut c_char {
    // construct the public key of all people
    let c_pubkeys = unsafe {
        assert!(!pubkeys.is_null());

        CStr::from_ptr(pubkeys)
    };

    let r_pubkeys_bytes = c_pubkeys.to_bytes();
    // ensure that it is the correct public key length
    assert!(r_pubkeys_bytes.len() % 32 == 0);
    let pubkeys_num = r_pubkeys_bytes.len() / 32;

    let mut pubkeys = Vec::<PublicKey>::new();
    for n in 0..pubkeys_num {
        let publickey = PublicKey::from_bytes(&r_pubkeys_bytes[n..n + 32]).unwrap();
        pubkeys.push(publickey);
    }

    let agg = aggregate_public_key_from_slice(&mut pubkeys).unwrap();
    let agg_pubkey = agg.public_key().to_bytes();
    let agg_hex = hex::encode(agg_pubkey);
    let c_agg_str = CString::new(agg_hex).unwrap();
    c_agg_str.into_raw()
}
