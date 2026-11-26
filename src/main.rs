//! Demo: starts a loopback TLS relay and three separate client processes.
//! Names and messages are fictional. Certificates exist only for this run.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::{fs, thread, time::Duration};
use talk_prototype::{
    pki::{ClientTls, TestPki},
    relay::{Conn, Relay},
    sync::{commit_with_retry, join_with_recovery, next_text, sync},
    Client, Event,
};

const HELLO: &str = "FICTIONAL-HELLO from Alice";
const BOB: &str = "FICTIONAL-REPLY from Bob";
const CAROL: &str = "FICTIONAL-REPLY from Carol";
const SECRET: &str = "FICTIONAL-AFTER-REMOVAL only Alice and Bob";
const PEOPLE: [&str; 3] = ["alice", "bob", "carol"];

type R<T> = Result<T, Box<dyn std::error::Error>>;

fn wait_file(p: &Path) -> R<Vec<u8>> {
    for _ in 0..3000 {
        if let Ok(d) = fs::read(p) {
            if !d.is_empty() {
                return Ok(d);
            }
        }
        thread::sleep(Duration::from_millis(5));
    }
    Err(format!("timed out waiting for {}", p.display()).into())
}

fn write_atomic(p: &Path, data: &[u8]) -> R<()> {
    let tmp = p.with_extension("part");
    fs::write(&tmp, data)?;
    fs::rename(tmp, p)?;
    Ok(())
}

/// Stands in for meeting in person: exchange cards, then compare safety codes.
fn verify_everyone(c: &mut Client, dir: &Path) -> R<()> {
    write_atomic(&dir.join(format!("{}.card", c.name)), &c.identity_card())?;
    let others: Vec<&str> = PEOPLE.iter().copied().filter(|p| *p != c.name).collect();
    let mut cards = Vec::new();
    for o in &others {
        let card = wait_file(&dir.join(format!("{o}.card")))?;
        write_atomic(&dir.join(format!("{}-to-{o}.code", c.name)), c.safety_code(&card)?.as_bytes())?;
        cards.push((*o, card));
    }
    for (o, card) in cards {
        let code = String::from_utf8(wait_file(&dir.join(format!("{o}-to-{}.code", c.name)))?)?;
        c.trust_contact(&card, &code)?;
    }
    Ok(())
}

fn start(name: &str, port: u16, dir: &Path) -> R<(Client, Conn)> {
    let mut c = Client::new(name)?;
    let n = Conn::connect(port, &ClientTls::load(dir, name)?)?;
    verify_everyone(&mut c, dir)?;
    Ok((c, n))
}

fn expect(c: &mut Client, n: &mut Conn, sender: &str, want: &str) -> R<()> {
    let mailbox = format!("in/{}", c.name);
    let (from, text) = next_text(c, n, &mailbox)?;
    if from != sender || text != want {
        return Err(format!("unexpected message from {from}").into());
    }
    println!("{} decrypted a message from {sender}", c.name);
    Ok(())
}

fn alice(port: u16, dir: &Path) -> R<()> {
    let (mut c, mut n) = start("alice", port, dir)?;
    println!("connection key exchange: {}", n.key_exchange());
    c.create_group(b"fictional-group")?;
    for person in ["bob", "carol"] {
        let package = n.get(&format!("kp/{person}"))?;
        let welcome = commit_with_retry(&mut c, &mut n, |c| {
            let (commit, welcome) = c.begin_add(&package)?;
            Ok((commit, Some(welcome)))
        })?
        .ok_or("no welcome")?;
        n.put(&format!("welcome/{person}"), &welcome)?;
    }
    let m = c.send(HELLO)?;
    n.put("in/bob", &m)?;
    n.put("in/carol", &m)?;
    expect(&mut c, &mut n, "bob", BOB)?;
    expect(&mut c, &mut n, "carol", CAROL)?;
    commit_with_retry(&mut c, &mut n, |c| Ok((c.begin_remove("carol")?, None)))?;
    let m = c.send(SECRET)?;
    n.put("in/bob", &m)?;
    n.put("in/carol", &m)?;
    Ok(())
}

fn bob(port: u16, dir: &Path) -> R<()> {
    let (mut c, mut n) = start("bob", port, dir)?;
    n.put("kp/bob", &c.key_package()?)?;
    join_with_recovery(&mut c, &mut n, "alice")?;
    expect(&mut c, &mut n, "alice", HELLO)?;
    let m = c.send(BOB)?;
    n.put("in/carol", &m)?;
    n.put("in/alice", &m)?;
    expect(&mut c, &mut n, "carol", CAROL)?;
    expect(&mut c, &mut n, "alice", SECRET)?;
    Ok(())
}

fn carol(port: u16, dir: &Path) -> R<()> {
    let (mut c, mut n) = start("carol", port, dir)?;
    n.put("kp/carol", &c.key_package()?)?;
    join_with_recovery(&mut c, &mut n, "alice")?;
    expect(&mut c, &mut n, "alice", HELLO)?;
    expect(&mut c, &mut n, "bob", BOB)?;
    let m = c.send(CAROL)?;
    n.put("in/bob", &m)?;
    n.put("in/alice", &m)?;
    for _ in 0..3000 {
        sync(&mut c, &mut n)?;
        if !c.is_active() {
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    if c.is_active() {
        return Err("carol should have been removed".into());
    }
    let after = n.get("in/carol")?;
    match c.receive(&after) {
        Ok(Event::Text { .. }) => Err("removed member read a later message".into()),
        _ => {
            println!("carol was removed and could not read the later message");
            Ok(())
        }
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn run_demo() -> R<bool> {
    let dir = PathBuf::from(std::env::temp_dir()).join(format!("talk-demo-{}", std::process::id()));
    fs::create_dir(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    }
    let result = (|| -> R<bool> {
        let mut pki = TestPki::new()?;
        for p in PEOPLE {
            pki.issue(p)?.save(&dir, p)?;
        }
        let relay = Relay::start(&pki)?;
        let exe = std::env::current_exe()?;
        let children: Vec<_> = PEOPLE
            .iter()
            .map(|r| Command::new(&exe).args([*r, &relay.port.to_string(), dir.to_str().unwrap()]).spawn())
            .collect::<Result<_, _>>()?;
        let mut ok = true;
        for mut c in children {
            ok &= c.wait()?.success();
        }
        let seen = relay.seen();
        let leaked = seen.iter().any(|d| {
            [HELLO, BOB, CAROL, SECRET].iter().any(|t| contains(d, t.as_bytes())) || contains(d, b"FICTIONAL")
        });
        println!("relay handled {} items; message text visible to relay: {leaked}", seen.len());
        Ok(ok && !leaked)
    })();
    fs::remove_dir_all(&dir)?;
    result
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 4 {
        let port: u16 = args[2].parse().expect("port");
        let dir = Path::new(&args[3]);
        let result = match args[1].as_str() {
            "alice" => alice(port, dir),
            "bob" => bob(port, dir),
            "carol" => carol(port, dir),
            _ => Err("unknown role".into()),
        };
        return match result {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("{} failed: {e}", args[1]);
                ExitCode::FAILURE
            }
        };
    }
    match run_demo() {
        Ok(true) => {
            println!("DEMO PASSED");
            ExitCode::SUCCESS
        }
        Ok(false) => {
            println!("DEMO FAILED");
            ExitCode::FAILURE
        }
        Err(e) => {
            println!("DEMO FAILED: {e}");
            ExitCode::FAILURE
        }
    }
}
