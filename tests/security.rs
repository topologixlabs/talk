//! Tests use fictional names and text. A rejected message must yield no plaintext.

use talk_prototype::*;

fn text(sender: &str, t: &str) -> Event {
    Event::Text { sender: sender.into(), text: t.into() }
}

fn pair() -> (Client, Client) {
    let (mut a, mut b) = (Client::new("alice").unwrap(), Client::new("bob").unwrap());
    meet_in_person(&mut a, &mut b).unwrap();
    a.create_group(b"test-group").unwrap();
    let (_, w) = a.add_member(&b.key_package().unwrap()).unwrap();
    b.join(&w).unwrap();
    (a, b)
}

fn trio() -> (Client, Client, Client) {
    let (mut a, mut b) = pair();
    let mut c = Client::new("carol").unwrap();
    meet_in_person(&mut a, &mut c).unwrap();
    meet_in_person(&mut b, &mut c).unwrap();
    let (commit, w) = a.add_member(&c.key_package().unwrap()).unwrap();
    b.receive(&commit).unwrap();
    c.join(&w).unwrap();
    (a, b, c)
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn two_clients_exchange_both_ways() {
    let (mut a, mut b) = pair();
    let m = a.send("hello bob").unwrap();
    assert_eq!(b.receive(&m).unwrap(), text("alice", "hello bob"));
    let m = b.send("hello alice").unwrap();
    assert_eq!(a.receive(&m).unwrap(), text("bob", "hello alice"));
}

#[test]
fn three_clients_share_a_group() {
    let (mut a, mut b, mut c) = trio();
    let m = c.send("hi all").unwrap();
    assert_eq!(a.receive(&m).unwrap(), text("carol", "hi all"));
    assert_eq!(b.receive(&m).unwrap(), text("carol", "hi all"));
    let s = a.export_secret().unwrap();
    assert_eq!(s, b.export_secret().unwrap());
    assert_eq!(s, c.export_secret().unwrap());
}

#[test]
fn group_uses_hybrid_post_quantum_suite() {
    let (a, b) = pair();
    assert_eq!(a.group_suite().unwrap(), u16::from(SUITE));
    assert_eq!(b.group_suite().unwrap(), u16::from(SUITE));
    assert_eq!(SUITE.hpke_kem_algorithm(), openmls_traits::types::HpkeKemType::XWingKemDraft6);
    // X-Wing public key: 1,184 bytes of ML-KEM-768 plus 32 bytes of X25519.
    let kp = Client::new("dana").unwrap().key_package().unwrap();
    assert_eq!(init_key_len(&kp).unwrap(), 1216);
}

#[test]
fn ciphertext_hides_text_and_repeats_differ() {
    let (mut a, _b) = pair();
    let (m1, m2) = (a.send("FICTIONAL-SECRET").unwrap(), a.send("FICTIONAL-SECRET").unwrap());
    assert!(!contains(&m1, b"FICTIONAL"));
    assert!(!contains(&m2, b"FICTIONAL"));
    assert_ne!(m1, m2);
}

#[test]
fn every_flipped_byte_is_rejected() {
    let (mut a, mut b) = pair();
    let m = a.send("do not change me").unwrap();
    for i in 0..m.len() {
        let mut bad = m.clone();
        bad[i] ^= 0x01;
        assert!(b.receive(&bad).is_err(), "tampered byte {i} was accepted");
    }
}

#[test]
fn genuine_message_still_arrives_after_tampered_copies() {
    let (mut a, mut b) = pair();
    let m = a.send("still deliverable").unwrap();
    for i in 0..m.len() {
        let mut bad = m.clone();
        bad[i] ^= 0x80;
        assert!(b.receive(&bad).is_err());
    }
    assert_eq!(b.receive(&m).unwrap(), text("alice", "still deliverable"));
}

#[test]
fn truncated_extended_and_garbage_are_rejected() {
    let (mut a, mut b) = pair();
    let m = a.send("complete").unwrap();
    for cut in [0, 1, m.len() / 2, m.len() - 1] {
        assert!(b.receive(&m[..cut]).is_err());
    }
    let mut longer = m.clone();
    longer.push(0);
    assert!(b.receive(&longer).is_err());
    assert!(b.receive(&[0xAB; 512]).is_err());
}

#[test]
fn replay_is_rejected() {
    let (mut a, mut b) = pair();
    let m = a.send("once only").unwrap();
    assert!(b.receive(&m).is_ok());
    assert!(b.receive(&m).is_err());
}

#[test]
fn outsider_with_wrong_keys_cannot_read() {
    let (mut a, _b) = pair();
    let mut outsider = Client::new("mallory").unwrap();
    outsider.create_group(b"test-group").unwrap(); // same group ID, different keys
    let m = a.send("private").unwrap();
    assert!(outsider.receive(&m).is_err());
}

#[test]
fn outsider_cannot_inject_a_message() {
    let (_a, mut b) = pair();
    let mut outsider = Client::new("mallory").unwrap();
    outsider.create_group(b"test-group").unwrap();
    let forged = outsider.send("trust me").unwrap();
    assert!(b.receive(&forged).is_err());
}

#[test]
fn message_from_another_group_is_rejected() {
    let (mut a, mut b) = pair();
    let (mut x, _y) = {
        let (mut x, mut y) = (Client::new("alice").unwrap(), Client::new("bob").unwrap());
        meet_in_person(&mut x, &mut y).unwrap();
        x.create_group(b"other-group").unwrap();
        let (_, w) = x.add_member(&y.key_package().unwrap()).unwrap();
        y.join(&w).unwrap();
        (x, y)
    };
    assert!(b.receive(&x.send("wrong group").unwrap()).is_err());
    assert!(b.receive(&a.send("right group").unwrap()).is_ok());
}

#[test]
fn welcome_for_bob_cannot_be_used_by_carol() {
    let mut a = Client::new("alice").unwrap();
    let mut b = Client::new("bob").unwrap();
    let mut c = Client::new("carol").unwrap();
    meet_in_person(&mut a, &mut b).unwrap();
    meet_in_person(&mut a, &mut c).unwrap();
    let _ = c.key_package().unwrap();
    a.create_group(b"test-group").unwrap();
    let (_, w) = a.add_member(&b.key_package().unwrap()).unwrap();
    assert!(c.join(&w).is_err());
}

#[test]
fn every_tampered_welcome_byte_is_rejected() {
    let mut a = Client::new("alice").unwrap();
    let mut template = Client::new("bob").unwrap();
    meet_in_person(&mut a, &mut template).unwrap();
    a.create_group(b"test-group").unwrap();
    let (_, w) = a.add_member(&template.key_package().unwrap()).unwrap();
    // The recipient's key is one-time, so each attempt needs a fresh invitation.
    for i in 0..w.len() {
        let mut inviter = Client::new("alice").unwrap();
        let mut bob = Client::new("bob").unwrap();
        meet_in_person(&mut inviter, &mut bob).unwrap();
        inviter.create_group(b"test-group").unwrap();
        let (_, fresh) = inviter.add_member(&bob.key_package().unwrap()).unwrap();
        let j = i.min(fresh.len() - 1);
        let mut bad = fresh.clone();
        bad[j] ^= 1;
        assert!(bob.join(&bad).is_err(), "tampered welcome byte {j} accepted");
    }
}

/// KNOWN LIMITATION: a relay can deny a join by tampering with an invitation,
/// because the rejected attempt consumes the one-time key. It cannot read anything.
#[test]
fn tampered_welcome_burns_key_but_re_invite_recovers() {
    let mut a = Client::new("alice").unwrap();
    let mut b = Client::new("bob").unwrap();
    meet_in_person(&mut a, &mut b).unwrap();
    a.create_group(b"test-group").unwrap();
    let (_, w) = a.add_member(&b.key_package().unwrap()).unwrap();
    let mut bad = w.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert!(b.join(&bad).is_err());
    let genuine = b.join(&w);
    assert!(genuine.unwrap_err().contains("NoMatchingKeyPackage"));
    a.remove_member("bob").unwrap();
    let (_, w2) = a.add_member(&b.key_package().unwrap()).unwrap();
    b.join(&w2).unwrap();
    let m = a.send("recovered").unwrap();
    assert_eq!(b.receive(&m).unwrap(), text("alice", "recovered"));
}

#[test]
fn tampered_key_package_is_rejected() {
    let kp = Client::new("bob").unwrap().key_package().unwrap();
    for i in 0..kp.len() {
        let mut bad = kp.clone();
        bad[i] ^= 1;
        assert!(validate_key_package(&bad).is_err(), "tampered key package byte {i} accepted");
    }
}

#[test]
fn tampered_commit_is_rejected_and_group_does_not_move() {
    let (mut a, mut b) = pair();
    let before = b.epoch().unwrap();
    let commit = a.update_keys().unwrap();
    for i in 0..commit.len() {
        let mut bad = commit.clone();
        bad[i] ^= 1;
        assert!(b.receive(&bad).is_err(), "tampered commit byte {i} accepted");
        assert_eq!(b.epoch().unwrap(), before);
    }
    b.receive(&commit).unwrap();
    assert_eq!(a.export_secret().unwrap(), b.export_secret().unwrap());
}

#[test]
fn removed_member_cannot_read_later_messages() {
    let (mut a, mut b, mut c) = trio();
    let commit = a.remove_member("carol").unwrap();
    b.receive(&commit).unwrap();
    assert_eq!(c.receive(&commit).unwrap(), Event::GroupChanged { still_member: false });
    assert!(!c.is_active());
    let m = a.send("after carol left").unwrap();
    assert!(c.receive(&m).is_err());
    assert_eq!(b.receive(&m).unwrap(), text("alice", "after carol left"));
    assert!(c.export_secret().is_err(), "a removed member must have no current group secret");
}

#[test]
fn new_member_cannot_read_earlier_messages() {
    let (mut a, mut b) = pair();
    let earlier = a.send("before carol joined").unwrap();
    b.receive(&earlier).unwrap();
    let mut c = Client::new("carol").unwrap();
    meet_in_person(&mut a, &mut c).unwrap();
    meet_in_person(&mut b, &mut c).unwrap();
    let (commit, w) = a.add_member(&c.key_package().unwrap()).unwrap();
    b.receive(&commit).unwrap();
    c.join(&w).unwrap();
    assert!(c.receive(&earlier).is_err());
}

#[test]
fn key_update_changes_group_secret_and_old_epoch_is_refused() {
    let (mut a, mut b) = pair();
    let old_secret = a.export_secret().unwrap();
    let old_message = b.send("sent in the old epoch").unwrap();
    let commit = a.update_keys().unwrap();
    b.receive(&commit).unwrap();
    assert_ne!(a.export_secret().unwrap(), old_secret);
    assert_eq!(a.export_secret().unwrap(), b.export_secret().unwrap());
    assert!(a.receive(&old_message).is_err());
}
