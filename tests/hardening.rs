//! Adversarial tests for identity, storage, relay access, recovery and ordering.
//! All names, passphrases and messages are fictional.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{Arc, Barrier};
use std::{fs, io::{Read, Write}, net::TcpStream, thread, time::Duration};
use talk_prototype::{pki::*, relay::*, sync::*, *};

const PASS: &str = "fictional test passphrase";

fn text(sender: &str, t: &str) -> Event {
    Event::Text { sender: sender.into(), text: t.into() }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn pair() -> (Client, Client) {
    let (mut a, mut b) = (Client::new("alice").unwrap(), Client::new("bob").unwrap());
    meet_in_person(&mut a, &mut b).unwrap();
    a.create_group(b"test-group").unwrap();
    let (_, w) = a.add_member(&b.key_package().unwrap()).unwrap();
    b.join(&w).unwrap();
    (a, b)
}

fn temp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("talk-test-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir(&d).unwrap();
    fs::set_permissions(&d, fs::Permissions::from_mode(0o700)).unwrap();
    d
}

struct Net { relay: Relay, tls: Vec<ClientTls>, pki: TestPki }

fn net(names: &[&str]) -> Net {
    let mut pki = TestPki::new().unwrap();
    let tls = names.iter().map(|n| pki.issue(n).unwrap()).collect();
    let relay = Relay::start(&pki).unwrap();
    Net { relay, tls, pki }
}

// ---------- Identity ----------

#[test]
fn safety_codes_match_on_both_sides() {
    let (a, b) = (Client::new("alice").unwrap(), Client::new("bob").unwrap());
    let code = a.safety_code(&b.identity_card()).unwrap();
    assert_eq!(code, b.safety_code(&a.identity_card()).unwrap());
    assert_eq!(code.replace(' ', "").len(), 40);
}

#[test]
fn swapped_identity_card_is_detected() {
    let (mut a, b) = (Client::new("alice").unwrap(), Client::new("bob").unwrap());
    let impostor = Client::new("bob").unwrap();
    let real_code = b.safety_code(&a.identity_card()).unwrap();
    assert_ne!(a.safety_code(&impostor.identity_card()).unwrap(), real_code);
    assert!(a.trust_contact(&impostor.identity_card(), &real_code).is_err());
}

#[test]
fn unverified_person_cannot_be_added() {
    let mut a = Client::new("alice").unwrap();
    let stranger = Client::new("bob").unwrap();
    a.create_group(b"test-group").unwrap();
    assert!(a.add_member(&stranger.key_package().unwrap()).unwrap_err().contains("unverified"));
}

#[test]
fn impersonator_using_a_verified_name_is_refused() {
    let (mut a, mut b) = (Client::new("alice").unwrap(), Client::new("bob").unwrap());
    meet_in_person(&mut a, &mut b).unwrap();
    let fake = Client::new("bob").unwrap();
    a.create_group(b"test-group").unwrap();
    assert!(a.add_member(&fake.key_package().unwrap()).unwrap_err().contains("unverified"));
}

#[test]
fn changed_key_needs_deliberate_reverification() {
    let (mut a, mut b) = (Client::new("alice").unwrap(), Client::new("bob").unwrap());
    meet_in_person(&mut a, &mut b).unwrap();
    let new_bob = Client::new("bob").unwrap();
    let code = new_bob.safety_code(&a.identity_card()).unwrap();
    assert!(a.trust_contact(&new_bob.identity_card(), &code).unwrap_err().contains("changed"));
    a.forget_contact("bob");
    a.trust_contact(&new_bob.identity_card(), &code).unwrap();
}

#[test]
fn join_is_refused_if_group_contains_unverified_member() {
    let (mut a, _b) = pair();
    let mut dana = Client::new("dana").unwrap();
    meet_in_person(&mut a, &mut dana).unwrap(); // Dana has verified Alice but not Bob
    let (_, w) = a.add_member(&dana.key_package().unwrap()).unwrap();
    assert!(dana.join(&w).unwrap_err().contains("unverified"));
}

#[test]
fn commit_adding_unverified_member_is_refused_by_others() {
    let (mut a, mut b) = pair();
    let mut carol = Client::new("carol").unwrap();
    meet_in_person(&mut a, &mut carol).unwrap(); // Bob has not verified Carol
    let before = b.epoch().unwrap();
    let (commit, _) = a.add_member(&carol.key_package().unwrap()).unwrap();
    assert!(b.receive(&commit).unwrap_err().contains("unverified"));
    assert_eq!(b.epoch().unwrap(), before);
}

// ---------- Encrypted storage ----------

#[test]
fn conversation_continues_after_save_and_reload() {
    let d = temp("reload");
    let (mut a, b) = pair();
    let path = d.join("bob.vault");
    b.save(&path, PASS).unwrap();
    drop(b);
    let mut b = Client::load(&path, PASS).unwrap();
    let m = a.send("after restart").unwrap();
    assert_eq!(b.receive(&m).unwrap(), text("alice", "after restart"));
    let m = b.send("reply after restart").unwrap();
    assert_eq!(a.receive(&m).unwrap(), text("bob", "reply after restart"));
    let c = a.update_keys().unwrap();
    b.receive(&c).unwrap();
    assert_eq!(a.export_secret().unwrap(), b.export_secret().unwrap());
    fs::remove_dir_all(d).unwrap();
}

#[test]
fn wrong_passphrase_is_rejected() {
    let d = temp("wrongpass");
    let (_a, b) = pair();
    let path = d.join("bob.vault");
    b.save(&path, PASS).unwrap();
    assert!(Client::load(&path, "another fictional passphrase").is_err());
    fs::remove_dir_all(d).unwrap();
}

#[test]
fn damaged_vault_is_rejected() {
    let d = temp("damaged");
    let (_a, b) = pair();
    let path = d.join("bob.vault");
    b.save(&path, PASS).unwrap();
    let good = fs::read(&path).unwrap();
    let last = good.len() - 1;
    for i in [0, 9, 25, 37, good.len() / 2, last] {
        let mut bad = good.clone();
        bad[i] ^= 1;
        fs::write(&path, &bad).unwrap();
        assert!(Client::load(&path, PASS).is_err(), "damaged byte {i} accepted");
    }
    fs::write(&path, &good[..good.len() - 1]).unwrap();
    assert!(Client::load(&path, PASS).is_err());
    fs::remove_dir_all(d).unwrap();
}

#[test]
fn vault_hides_contents_and_is_owner_only() {
    let d = temp("hidden");
    let (_a, b) = pair();
    let path = d.join("bob.vault");
    b.save(&path, PASS).unwrap();
    let data = fs::read(&path).unwrap();
    assert!(!contains(&data, b"alice"));
    assert!(!contains(&data, b"test-group"));
    assert!(!contains(&data, &b.identity_card()[7..]), "signing public key visible");
    assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    fs::remove_dir_all(d).unwrap();
}

// ---------- Relay access ----------

#[test]
fn connection_uses_post_quantum_tls() {
    let n = net(&["alice"]);
    let c = Conn::connect(n.relay.port, &n.tls[0]).unwrap();
    assert!(c.key_exchange().contains("X25519MLKEM768"), "got {}", c.key_exchange());
}

#[test]
fn plaintext_connection_gets_no_service() {
    let n = net(&["alice"]);
    let mut s = TcpStream::connect(("127.0.0.1", n.relay.port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(&[2, 0, 8]).unwrap();
    s.write_all(b"in/alice").unwrap();
    let mut buf = [0u8; 64];
    let got = s.read(&mut buf).unwrap_or(0);
    assert!(got == 0 || buf[0] == 0x15, "relay answered a non-TLS client");
}

#[test]
fn client_without_certificate_is_refused() {
    let n = net(&["alice"]);
    let result = Conn::connect(n.relay.port, &n.tls[0].without_certificate())
        .and_then(|mut c| c.try_get("in/alice").map_err(|e| e.to_string()));
    assert!(result.is_err());
}

#[test]
fn certificate_from_another_authority_is_refused() {
    let n = net(&["alice"]);
    let mut other = TestPki::new().unwrap();
    let mut forged = other.issue("alice").unwrap();
    forged.ca_der = n.tls[0].ca_der.clone();
    let result = Conn::connect(n.relay.port, &forged)
        .and_then(|mut c| c.try_get("in/alice").map_err(|e| e.to_string()));
    assert!(result.is_err());
}

#[test]
fn valid_certificate_without_account_is_refused() {
    let n = net(&["alice"]);
    let ghost = n.pki.issue_unregistered("alice").unwrap();
    let result = Conn::connect(n.relay.port, &ghost)
        .and_then(|mut c| c.try_get("in/alice").map_err(|e| e.to_string()));
    assert!(result.is_err());
}

#[test]
fn client_refuses_a_fake_relay() {
    let n = net(&["alice"]);
    let mut other = TestPki::new().unwrap();
    let wrong_trust = other.issue("alice").unwrap();
    let mut tls = n.tls[0].clone();
    tls.ca_der = wrong_trust.ca_der;
    assert!(Conn::connect(n.relay.port, &tls).is_err());
}

#[test]
fn cannot_read_another_persons_mailbox() {
    let n = net(&["alice", "bob"]);
    let mut alice = Conn::connect(n.relay.port, &n.tls[0]).unwrap();
    let mut bob = Conn::connect(n.relay.port, &n.tls[1]).unwrap();
    alice.put("in/bob", b"sealed").unwrap();
    for m in ["in/bob", "welcome/bob", "reinvite/bob"] {
        assert_eq!(alice.try_get(m).unwrap_err().kind(), std::io::ErrorKind::PermissionDenied);
    }
    assert_eq!(bob.try_get("in/bob").unwrap().unwrap(), b"sealed");
}

#[test]
fn cannot_publish_a_key_package_for_someone_else() {
    let n = net(&["alice", "bob"]);
    let mut alice = Conn::connect(n.relay.port, &n.tls[0]).unwrap();
    assert_eq!(alice.put("kp/bob", b"fake").unwrap_err().kind(), std::io::ErrorKind::PermissionDenied);
    assert_eq!(alice.put("in/nobody", b"x").unwrap_err().kind(), std::io::ErrorKind::PermissionDenied);
    assert_eq!(alice.put("admin/bob", b"x").unwrap_err().kind(), std::io::ErrorKind::PermissionDenied);
}

#[test]
fn rate_limit_applies() {
    let mut pki = TestPki::new().unwrap();
    let (a, _b) = (pki.issue("alice").unwrap(), pki.issue("bob").unwrap());
    let relay = Relay::start_with_limit(&pki, 5.0).unwrap();
    let mut c = Conn::connect(relay.port, &a).unwrap();
    let limited = (0..30).filter(|_| {
        matches!(c.put("in/bob", b"x"), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock)
    }).count();
    assert!(limited >= 20, "only {limited} of 30 were limited");
}

#[test]
fn full_mailbox_refuses_more() {
    let n = net(&["alice", "bob"]);
    let mut c = Conn::connect(n.relay.port, &n.tls[0]).unwrap();
    for _ in 0..MAX_QUEUE {
        c.put("in/bob", b"x").unwrap();
    }
    assert_eq!(c.put("in/bob", b"x").unwrap_err().kind(), std::io::ErrorKind::StorageFull);
}

#[test]
fn oversized_frame_closes_the_connection() {
    let n = net(&["alice", "bob"]);
    let mut c = Conn::connect(n.relay.port, &n.tls[0]).unwrap();
    assert!(c.send_oversized_header("in/bob").is_err());
}

// ---------- Invitation recovery ----------

fn invite_setup() -> (Net, Client, Client) {
    let n = net(&["alice", "bob"]);
    let (mut a, mut b) = (Client::new("alice").unwrap(), Client::new("bob").unwrap());
    meet_in_person(&mut a, &mut b).unwrap();
    a.create_group(b"test-group").unwrap();
    (n, a, b)
}

#[test]
fn tampered_invitation_recovers_automatically() {
    let (n, mut a, mut b) = invite_setup();
    let mut na = Conn::connect(n.relay.port, &n.tls[0]).unwrap();
    let mut nb = Conn::connect(n.relay.port, &n.tls[1]).unwrap();
    let package = b.key_package().unwrap();
    let w = commit_with_retry(&mut a, &mut na, |c| {
        let (commit, welcome) = c.begin_add(&package)?;
        Ok((commit, Some(welcome)))
    }).unwrap().unwrap();
    na.put("welcome/bob", &w).unwrap();
    assert!(n.relay.tamper_next("welcome/bob", w.len() - 1));

    let joiner = thread::spawn(move || { join_with_recovery(&mut b, &mut nb, "alice").unwrap(); (b, nb) });
    let mut served = 0;
    for _ in 0..1000 {
        served += serve_reinvites(&mut a, &mut na).unwrap();
        if served > 0 { break; }
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(served, 1);
    let (mut b, mut nb) = joiner.join().unwrap();
    sync(&mut b, &mut nb).unwrap();
    let m = a.send("recovered automatically").unwrap();
    assert_eq!(b.receive(&m).unwrap(), text("alice", "recovered automatically"));
}

#[test]
fn replayed_reinvite_is_refused() {
    let (mut a, mut b) = pair();
    let package = b.key_package().unwrap();
    assert_eq!(a.accept_reinvite(&package).unwrap(), "bob");
    assert!(a.accept_reinvite(&package).unwrap_err().contains("already used"));
    b.forget_contact("nobody");
}

#[test]
fn reinvite_from_unverified_person_is_refused() {
    let (mut a, _b) = pair();
    let fake = Client::new("bob").unwrap();
    assert!(a.accept_reinvite(&fake.key_package().unwrap()).unwrap_err().contains("unverified"));
}

#[test]
fn reinvite_requests_are_capped() {
    let (mut a, b) = pair();
    for _ in 0..MAX_REINVITES {
        a.accept_reinvite(&b.key_package().unwrap()).unwrap();
    }
    assert!(a.accept_reinvite(&b.key_package().unwrap()).unwrap_err().contains("too many"));
}

// ---------- Ordering ----------

#[test]
fn simultaneous_group_changes_converge() {
    let n = net(&["alice", "bob", "carol"]);
    let (mut a, mut b, mut c) = (Client::new("alice").unwrap(), Client::new("bob").unwrap(), Client::new("carol").unwrap());
    meet_in_person(&mut a, &mut b).unwrap();
    meet_in_person(&mut a, &mut c).unwrap();
    meet_in_person(&mut b, &mut c).unwrap();
    let mut na = Conn::connect(n.relay.port, &n.tls[0]).unwrap();
    a.create_group(b"test-group").unwrap();
    let pb = b.key_package().unwrap();
    let wb = commit_with_retry(&mut a, &mut na, |x| { let (m, w) = x.begin_add(&pb)?; Ok((m, Some(w))) }).unwrap().unwrap();
    b.join(&wb).unwrap();
    let pc = c.key_package().unwrap();
    let wc = commit_with_retry(&mut a, &mut na, |x| { let (m, w) = x.begin_add(&pc)?; Ok((m, Some(w))) }).unwrap().unwrap();
    c.join(&wc).unwrap();
    let start_epoch = a.epoch().unwrap();

    let barrier = Arc::new(Barrier::new(3));
    let handles: Vec<_> = vec![(a, n.tls[0].clone()), (b, n.tls[1].clone()), (c, n.tls[2].clone())]
        .into_iter()
        .map(|(mut client, tls)| {
            let (port, gate) = (n.relay.port, barrier.clone());
            thread::spawn(move || {
                let mut conn = Conn::connect(port, &tls).unwrap();
                gate.wait();
                for _ in 0..5 {
                    commit_with_retry(&mut client, &mut conn, |x| Ok((x.begin_update()?, None))).unwrap();
                }
                (client, conn)
            })
        })
        .collect();
    let mut done: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    for (client, conn) in &mut done {
        sync(client, conn).unwrap();
    }
    let epoch = done[0].0.epoch().unwrap();
    assert_eq!(epoch, start_epoch + 15, "each of the 15 changes must apply exactly once");
    let secret = done[0].0.export_secret().unwrap();
    let check = done[0].0.group_check_code().unwrap();
    for (client, _) in &done {
        assert_eq!(client.epoch().unwrap(), epoch);
        assert_eq!(client.export_secret().unwrap(), secret);
        assert_eq!(client.group_check_code().unwrap(), check);
    }
    let m = done[1].0.send("all converged").unwrap();
    assert_eq!(done[0].0.receive(&m).unwrap(), text("bob", "all converged"));
    assert_eq!(done[2].0.receive(&m).unwrap(), text("bob", "all converged"));
}

#[test]
fn losing_commit_is_discarded_and_retried() {
    let n = net(&["alice", "bob"]);
    let (mut a, mut b) = pair();
    let mut na = Conn::connect(n.relay.port, &n.tls[0]).unwrap();
    let mut nb = Conn::connect(n.relay.port, &n.tls[1]).unwrap();
    let log = a.log_name().unwrap();
    let e = a.epoch().unwrap();
    let (ca, cb) = (a.begin_update().unwrap(), b.begin_update().unwrap());
    assert_eq!(na.submit_commit(&log, e, &ca).unwrap(), Some(0));
    assert_eq!(nb.submit_commit(&log, e, &cb).unwrap(), Some(1));
    a.confirm_commit().unwrap();
    b.abort_commit().unwrap();
    assert_eq!(sync(&mut b, &mut nb).unwrap(), 1);
    assert_eq!(a.export_secret().unwrap(), b.export_secret().unwrap());
}

#[test]
fn junk_group_change_cannot_block_the_group() {
    let n = net(&["alice", "bob", "mallory"]);
    let (mut a, mut b) = pair();
    let mut na = Conn::connect(n.relay.port, &n.tls[0]).unwrap();
    let mut nb = Conn::connect(n.relay.port, &n.tls[1]).unwrap();
    let mut nm = Conn::connect(n.relay.port, &n.tls[2]).unwrap();
    let log = a.log_name().unwrap();
    assert_eq!(nm.submit_commit(&log, a.epoch().unwrap(), &[0xAB; 300]).unwrap(), Some(0));
    commit_with_retry(&mut a, &mut na, |x| Ok((x.begin_update()?, None))).unwrap();
    assert_eq!(sync(&mut b, &mut nb).unwrap(), 1);
    assert_eq!(a.export_secret().unwrap(), b.export_secret().unwrap());
}

#[test]
fn ordinary_message_posted_as_group_change_is_ignored() {
    let n = net(&["alice", "bob"]);
    let (mut a, mut b) = pair();
    let mut na = Conn::connect(n.relay.port, &n.tls[0]).unwrap();
    let mut nb = Conn::connect(n.relay.port, &n.tls[1]).unwrap();
    let m = a.send("not a group change").unwrap();
    na.submit_commit(&a.log_name().unwrap(), a.epoch().unwrap(), &m).unwrap();
    assert_eq!(sync(&mut b, &mut nb).unwrap(), 0);
    assert_eq!(b.receive(&m).unwrap(), text("alice", "not a group change"));
}

#[test]
fn one_candidate_per_account_per_epoch() {
    let n = net(&["mallory"]);
    let mut c = Conn::connect(n.relay.port, &n.tls[0]).unwrap();
    assert_eq!(c.submit_commit("log/ab", 7, b"one").unwrap(), Some(0));
    assert_eq!(c.submit_commit("log/ab", 7, b"two").unwrap(), None);
}

#[test]
fn offline_member_reads_everything_in_order() {
    let n = net(&["alice", "bob"]);
    let (mut a, mut b) = pair();
    let mut na = Conn::connect(n.relay.port, &n.tls[0]).unwrap();
    let mut nb = Conn::connect(n.relay.port, &n.tls[1]).unwrap();
    // Bob is offline for three group changes, with messages before and after each.
    na.put("in/bob", &a.send("message 0").unwrap()).unwrap();
    for i in 1..=3 {
        commit_with_retry(&mut a, &mut na, |x| Ok((x.begin_update()?, None))).unwrap();
        na.put("in/bob", &a.send(&format!("message {i}")).unwrap()).unwrap();
    }
    for i in 0..=3 {
        assert_eq!(next_text(&mut b, &mut nb, "in/bob").unwrap(), ("alice".to_string(), format!("message {i}")));
    }
    assert_eq!(a.export_secret().unwrap(), b.export_secret().unwrap());
}

#[test]
fn message_arriving_before_its_group_change_is_delivered() {
    let n = net(&["alice", "bob"]);
    let (mut a, mut b) = pair();
    let mut na = Conn::connect(n.relay.port, &n.tls[0]).unwrap();
    let mut nb = Conn::connect(n.relay.port, &n.tls[1]).unwrap();
    commit_with_retry(&mut a, &mut na, |x| Ok((x.begin_update()?, None))).unwrap();
    na.put("in/bob", &a.send("early arrival").unwrap()).unwrap();
    assert_eq!(next_text(&mut b, &mut nb, "in/bob").unwrap().1, "early arrival");
}

#[test]
fn damaged_item_does_not_stop_later_delivery() {
    let n = net(&["alice", "bob"]);
    let (mut a, mut b) = pair();
    let mut na = Conn::connect(n.relay.port, &n.tls[0]).unwrap();
    let mut nb = Conn::connect(n.relay.port, &n.tls[1]).unwrap();
    let good = a.send("still arrives").unwrap();
    let mut bad = good.clone();
    *bad.last_mut().unwrap() ^= 1;
    na.put("in/bob", &[0xAB; 64]).unwrap();
    na.put("in/bob", &bad).unwrap();
    na.put("in/bob", &good).unwrap();
    assert_eq!(next_text(&mut b, &mut nb, "in/bob").unwrap().1, "still arrives");
}

#[test]
fn relay_refuses_a_public_bind_address() {
    let pki = TestPki::new().unwrap();
    let out = Relay::start_bound(&pki.ca_der, &pki.server_cert, &pki.server_key, pki.accounts.clone(),
        std::net::Ipv4Addr::UNSPECIFIED, 0, 10.0);
    assert!(out.is_err());
}

#[test]
fn relay_forking_the_group_is_detectable() {
    let (mut a, mut b) = pair();
    // A dishonest relay tells each member that their own conflicting change won.
    let _ = (a.begin_update().unwrap(), b.begin_update().unwrap());
    a.confirm_commit().unwrap();
    b.confirm_commit().unwrap();
    assert_eq!(a.epoch().unwrap(), b.epoch().unwrap());
    assert_ne!(a.group_check_code().unwrap(), b.group_check_code().unwrap());
    let m = a.send("across the fork").unwrap();
    assert!(b.receive(&m).is_err());
}

#[test]
fn held_message_buffer_is_bounded() {
    let (mut a, mut b) = pair();
    let c = a.update_keys().unwrap();
    let future = a.send("future").unwrap();
    for _ in 0..MAX_HELD {
        assert_eq!(b.receive_or_hold(&future).unwrap(), None);
    }
    assert!(b.receive_or_hold(&future).is_err());
    b.receive(&c).unwrap();
    // Only one copy can decrypt; replays are dropped.
    assert_eq!(b.drain_held(), vec![text("alice", "future")]);
    assert_eq!(b.held_count(), 0);
}

// ---------- End to end ----------

#[test]
fn relay_never_sees_text_over_tls() {
    let n = net(&["alice", "bob"]);
    let (mut a, mut b) = pair();
    let mut na = Conn::connect(n.relay.port, &n.tls[0]).unwrap();
    let mut nb = Conn::connect(n.relay.port, &n.tls[1]).unwrap();
    na.put("in/bob", &a.send("FICTIONAL-OVER-TLS").unwrap()).unwrap();
    assert_eq!(b.receive(&nb.get("in/bob").unwrap()).unwrap(), text("alice", "FICTIONAL-OVER-TLS"));
    assert!(n.relay.seen().iter().all(|d| !contains(d, b"FICTIONAL")));
    let replay = n.relay.seen()[0].clone();
    n.relay.inject("in/bob", replay);
    assert!(b.receive(&nb.get("in/bob").unwrap()).is_err());
}
