//! Two-device test over a private network. Names and messages are fictional.
//! Modes: issue, relay, alice, bob, device, probe.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use std::{fs, thread};
use talk_prototype::{
    pki::{ClientTls, TestPki},
    relay::{Conn, Relay},
    sync::{commit_with_retry, next_text, poll_texts, sync},
    Client, Event,
};

type R<T> = Result<T, Box<dyn std::error::Error>>;
const MARK: &str = "FICTIONAL-LINK";
const VAULT_PASS: &str = "fictional link test passphrase";
const ROUNDS: usize = 200;

fn wait_file(p: &Path) -> R<Vec<u8>> {
    for _ in 0..12000 {
        if let Ok(d) = fs::read(p) {
            if !d.is_empty() {
                return Ok(d);
            }
        }
        thread::sleep(Duration::from_millis(5));
    }
    Err(format!("timed out waiting for {}", p.display()).into())
}

fn write_atomic(p: &Path, d: &[u8]) -> R<()> {
    let t = p.with_extension("part");
    fs::write(&t, d)?;
    fs::rename(t, p)?;
    Ok(())
}

/// Identity cards and codes travel over SSH, a channel separate from the relay.
fn verify_peer(c: &mut Client, dir: &Path, peer: &str) -> R<()> {
    write_atomic(&dir.join(format!("{}.card", c.name)), &c.identity_card())?;
    let card = wait_file(&dir.join(format!("{peer}.card")))?;
    write_atomic(&dir.join(format!("{}.code", c.name)), c.safety_code(&card)?.as_bytes())?;
    let code = String::from_utf8(wait_file(&dir.join(format!("{peer}.code")))?)?;
    c.trust_contact(&card, &code)?;
    println!("RESULT {} verified_peer=yes", c.name);
    Ok(())
}

fn expect(c: &mut Client, n: &mut Conn, want: &str) -> R<()> {
    let mailbox = format!("in/{}", c.name);
    let (_, text) = next_text(c, n, &mailbox)?;
    if text != want {
        return Err(format!("expected {want:?}, got {text:?}").into());
    }
    Ok(())
}

fn say(c: &mut Client, n: &mut Conn, to: &str, text: &str) -> R<()> {
    let m = c.send(text)?;
    n.put(&format!("in/{to}"), &m)?;
    Ok(())
}

fn updates_then_settle(c: &mut Client, n: &mut Conn, start: u64) -> R<()> {
    for _ in 0..5 {
        commit_with_retry(c, n, |x| Ok((x.begin_update()?, None)))?;
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    while c.epoch()? < start + 10 {
        sync(c, n)?;
        if Instant::now() > deadline {
            return Err("group changes did not settle".into());
        }
        thread::sleep(Duration::from_millis(5));
    }
    Ok(())
}

fn write_check(c: &Client, dir: &Path) -> R<()> {
    let hex: String = c.group_check_code()?.iter().map(|b| format!("{b:02x}")).collect();
    write_atomic(&dir.join(format!("{}.check", c.name)), format!("{} {hex}", c.epoch()?).as_bytes())
}

fn alice(dir: &Path, host: Ipv4Addr, port: u16) -> R<()> {
    let mut c = Client::new("alice")?;
    let mut n = Conn::connect_host(host, port, &ClientTls::load(dir, "alice")?)?;
    println!("RESULT connection_key_exchange={}", n.key_exchange());
    verify_peer(&mut c, dir, "bob")?;
    let package = n.get("kp/bob")?;
    c.create_group(b"fictional-link")?;
    let welcome = commit_with_retry(&mut c, &mut n, |x| {
        let (m, w) = x.begin_add(&package)?;
        Ok((m, Some(w)))
    })?
    .ok_or("no welcome")?;
    n.put("welcome/bob", &welcome)?;
    say(&mut c, &mut n, "bob", &format!("{MARK} hello from the Mac"))?;
    expect(&mut c, &mut n, &format!("{MARK} hello from the Spark"))?;
    println!("RESULT two_way_message=yes");

    let mut times = Vec::with_capacity(ROUNDS);
    for i in 0..ROUNDS {
        let t = Instant::now();
        say(&mut c, &mut n, "bob", &format!("{MARK} ping {i}"))?;
        expect(&mut c, &mut n, &format!("{MARK} pong {i}"))?;
        times.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    times.sort_by(f64::total_cmp);
    println!("RESULT encrypted_round_trips={ROUNDS} median_ms={:.1} p95_ms={:.1}", times[ROUNDS / 2], times[ROUNDS * 95 / 100]);

    let good = c.send(&format!("{MARK} after tamper"))?;
    let mut bad = good.clone();
    *bad.last_mut().ok_or("empty")? ^= 1;
    n.put("in/bob", &bad)?;
    n.put("in/bob", &good)?;
    expect(&mut c, &mut n, &format!("{MARK} tamper rejected"))?;
    println!("RESULT tampered_message_rejected_by_spark=yes");

    say(&mut c, &mut n, "bob", &format!("{MARK} start changes"))?;
    expect(&mut c, &mut n, &format!("{MARK} ready"))?;
    let start = c.epoch()?;
    updates_then_settle(&mut c, &mut n, start)?;
    write_check(&c, dir)?;
    say(&mut c, &mut n, "bob", &format!("{MARK} after changes"))?;
    expect(&mut c, &mut n, &format!("{MARK} after changes ack"))?;
    println!("RESULT simultaneous_group_changes=10 converged=yes");

    say(&mut c, &mut n, "bob", &format!("{MARK} go offline"))?;
    expect(&mut c, &mut n, &format!("{MARK} offline now"))?;
    for i in 0..3 {
        say(&mut c, &mut n, "bob", &format!("{MARK} queued {i}"))?;
        commit_with_retry(&mut c, &mut n, |x| Ok((x.begin_update()?, None)))?;
    }
    say(&mut c, &mut n, "bob", &format!("{MARK} queued 3"))?;
    expect(&mut c, &mut n, &format!("{MARK} caught up"))?;
    println!("RESULT spark_restart_and_offline_catch_up=yes");

    commit_with_retry(&mut c, &mut n, |x| Ok((x.begin_remove("bob")?, None)))?;
    say(&mut c, &mut n, "bob", &format!("{MARK} after removal"))?;
    Ok(())
}

fn bob(dir: &Path, host: Ipv4Addr, port: u16) -> R<()> {
    let tls = ClientTls::load(dir, "bob")?;
    let mut c = Client::new("bob")?;
    let mut n = Conn::connect_host(host, port, &tls)?;
    verify_peer(&mut c, dir, "alice")?;
    n.put("kp/bob", &c.key_package()?)?;
    c.join(&n.get("welcome/bob")?)?;
    sync(&mut c, &mut n)?;
    expect(&mut c, &mut n, &format!("{MARK} hello from the Mac"))?;
    say(&mut c, &mut n, "alice", &format!("{MARK} hello from the Spark"))?;
    for i in 0..ROUNDS {
        expect(&mut c, &mut n, &format!("{MARK} ping {i}"))?;
        say(&mut c, &mut n, "alice", &format!("{MARK} pong {i}"))?;
    }

    let bad = n.get("in/bob")?;
    if c.receive(&bad).is_ok() {
        return Err("tampered message was accepted".into());
    }
    expect(&mut c, &mut n, &format!("{MARK} after tamper"))?;
    say(&mut c, &mut n, "alice", &format!("{MARK} tamper rejected"))?;

    expect(&mut c, &mut n, &format!("{MARK} start changes"))?;
    let start = c.epoch()?;
    say(&mut c, &mut n, "alice", &format!("{MARK} ready"))?;
    updates_then_settle(&mut c, &mut n, start)?;
    write_check(&c, dir)?;
    expect(&mut c, &mut n, &format!("{MARK} after changes"))?;
    say(&mut c, &mut n, "alice", &format!("{MARK} after changes ack"))?;

    expect(&mut c, &mut n, &format!("{MARK} go offline"))?;
    say(&mut c, &mut n, "alice", &format!("{MARK} offline now"))?;
    let vault = dir.join("bob.vault");
    c.save(&vault, VAULT_PASS)?;
    drop(c);
    drop(n);
    thread::sleep(Duration::from_secs(3));
    let mut c = Client::load(&vault, VAULT_PASS)?;
    let mut n = Conn::connect_host(host, port, &tls)?;
    for i in 0..4 {
        expect(&mut c, &mut n, &format!("{MARK} queued {i}"))?;
    }
    say(&mut c, &mut n, "alice", &format!("{MARK} caught up"))?;

    let deadline = Instant::now() + Duration::from_secs(30);
    while c.is_active() {
        sync(&mut c, &mut n)?;
        if Instant::now() > deadline {
            return Err("removal did not arrive".into());
        }
        thread::sleep(Duration::from_millis(5));
    }
    let after = n.get("in/bob")?;
    match c.receive(&after) {
        Ok(Event::Text { .. }) => Err("removed device read a later message".into()),
        _ => {
            println!("RESULT removed_device_cannot_read_new_message=yes");
            Ok(())
        }
    }
}

fn issue(dir: &Path, ip: &str) -> R<()> {
    let mut pki = TestPki::for_names(&[ip])?;
    for name in ["alice", "bob"] {
        pki.issue(name)?.save(dir, name)?;
    }
    fs::write(dir.join("server.crt"), &pki.server_cert)?;
    talk_prototype::pki::write_private(&dir.join("server.key"), &pki.server_key)?;
    // Save a certificate from a different authority for the refusal test.
    let mut other = TestPki::for_names(&[ip])?;
    let forged = other.issue("alice")?;
    fs::write(dir.join("forged.crt"), forged.cert_der.ok_or("no cert")?)?;
    talk_prototype::pki::write_private(&dir.join("forged.key"), &forged.key_der.ok_or("no key")?)?;
    Ok(())
}

fn relay(dir: &Path, ip: Ipv4Addr, port: u16, seconds: u64) -> R<()> {
    let names = fs::read_to_string(dir.join("accounts.txt")).unwrap_or_else(|_| "alice\nbob\n".into());
    let mut accounts = HashMap::new();
    for name in names.split_whitespace() {
        accounts.insert(fs::read(dir.join(format!("{name}.crt")))?, name.to_string());
    }
    let r = Relay::start_bound(
        &fs::read(dir.join("ca.der"))?,
        &fs::read(dir.join("server.crt"))?,
        &fs::read(dir.join("server.key"))?,
        accounts,
        ip,
        port,
        2000.0,
    )?;
    println!("RESULT relay_listening={ip}:{}", r.port);
    std::io::stdout().flush()?;
    let end = Instant::now() + Duration::from_secs(seconds);
    while Instant::now() < end && !dir.join("stop").exists() {
        thread::sleep(Duration::from_millis(100));
    }
    let seen = r.seen();
    let bytes: usize = seen.iter().map(Vec::len).sum();
    let leaked = seen.iter().any(|d| d.windows(MARK.len()).any(|w| w == MARK.as_bytes()));
    println!("RESULT relay_items={} relay_bytes={bytes} message_text_visible_to_relay={leaked}", seen.len());
    Ok(())
}

fn wait_or_stop(path: &Path, dir: &Path, end: Instant) -> R<Vec<u8>> {
    while Instant::now() < end && !dir.join("stop").exists() {
        if let Ok(d) = fs::read(path) {
            if !d.is_empty() {
                return Ok(d);
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err("stopped".into())
}

/// The Spark side of the app's device link. It never writes message text to disk.
fn device(dir: &Path, host: Ipv4Addr, port: u16, seconds: u64) -> R<()> {
    let end = Instant::now() + Duration::from_secs(seconds);
    let tls = ClientTls::load(dir, "spark")?;
    let mut n = None;
    for _ in 0..60 {
        if let Ok(c) = Conn::connect_host(host, port, &tls) {
            n = Some(c);
            break;
        }
        thread::sleep(Duration::from_millis(150));
    }
    let mut n = n.ok_or("relay unavailable")?;
    let mut c = Client::new("spark")?;
    write_atomic(&dir.join("spark.card"), &c.identity_card())?;
    let card = wait_or_stop(&dir.join("mac.card"), dir, end)?;
    write_atomic(&dir.join("spark.code"), c.safety_code(&card)?.as_bytes())?;
    // Keep the relay connection alive while the person compares the codes.
    while !dir.join("mac.code").exists() {
        if Instant::now() >= end || dir.join("stop").exists() {
            return Ok(());
        }
        n.try_get("in/spark")?;
        thread::sleep(Duration::from_millis(250));
    }
    let code = String::from_utf8(wait_or_stop(&dir.join("mac.code"), dir, end)?)?;
    c.trust_contact(&card, &code)?;
    n.put("kp/spark", &c.key_package()?)?;
    let welcome = loop {
        if Instant::now() >= end || dir.join("stop").exists() {
            return Ok(());
        }
        if let Some(w) = n.try_get("welcome/spark")? {
            break w;
        }
        thread::sleep(Duration::from_millis(30));
    };
    c.join(&welcome)?;
    while Instant::now() < end && !dir.join("stop").exists() && c.is_active() {
        for (sender, text) in poll_texts(&mut c, &mut n, "in/spark")? {
            if sender == "mac" {
                let reply = format!("Decrypted on spark-a: {text}");
                let m = c.send(&reply)?;
                n.put("in/mac", &m)?;
            }
        }
        thread::sleep(Duration::from_millis(40));
    }
    Ok(())
}

fn refused(result: Result<Conn, String>) -> bool {
    match result {
        Err(_) => true,
        Ok(mut c) => c.try_get("in/alice").is_err(),
    }
}

fn probe(dir: &Path, host: Ipv4Addr, port: u16) -> R<()> {
    let good = ClientTls::load(dir, "alice")?;
    println!("RESULT no_certificate_refused={}", refused(Conn::connect_host(host, port, &good.without_certificate())));
    let forged = ClientTls {
        ca_der: good.ca_der.clone(),
        cert_der: Some(fs::read(dir.join("forged.crt"))?),
        key_der: Some(fs::read(dir.join("forged.key"))?),
    };
    println!("RESULT forged_certificate_refused={}", refused(Conn::connect_host(host, port, &forged)));
    let mut s = TcpStream::connect_timeout(&(host, port).into(), Duration::from_secs(5))?;
    s.set_read_timeout(Some(Duration::from_secs(3)))?;
    s.write_all(&[2, 0, 8])?;
    s.write_all(b"in/alice")?;
    let mut buf = [0u8; 16];
    let got = s.read(&mut buf).unwrap_or(0);
    println!("RESULT plaintext_client_refused={}", got == 0 || buf[0] == 0x15);
    Ok(())
}

fn main() -> std::process::ExitCode {
    let a: Vec<String> = std::env::args().collect();
    let run = || -> R<()> {
        let mode = a.get(1).ok_or("mode")?.as_str();
        let dir = PathBuf::from(a.get(2).ok_or("dir")?);
        let ip = a.get(3).ok_or("ip")?;
        if mode == "issue" {
            return issue(&dir, ip);
        }
        let host: Ipv4Addr = ip.parse()?;
        let port: u16 = a.get(4).ok_or("port")?.parse()?;
        match mode {
            "relay" => relay(&dir, host, port, a.get(5).ok_or("seconds")?.parse()?),
            "alice" => alice(&dir, host, port),
            "bob" => bob(&dir, host, port),
            "device" => device(&dir, host, port, a.get(5).ok_or("seconds")?.parse()?),
            "probe" => probe(&dir, host, port),
            _ => Err("unknown mode".into()),
        }
    };
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("FAILED {}: {e}", a.get(1).map_or("", String::as_str));
            std::process::ExitCode::FAILURE
        }
    }
}
