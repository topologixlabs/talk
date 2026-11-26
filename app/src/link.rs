//! A private link from this Mac to spark-a over Tailscale. Keys for the link exist only
//! in memory. The temporary relay and companion on the Spark remove themselves.

use serde_json::{json, Value};
use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use talk_prototype::{
    pki::{ClientTls, TestPki},
    relay::Conn,
    sync::{commit_with_retry, poll_texts},
    vault, Client,
};

// The test machine is set at build time and never stored in the source. package-mac.sh
// reads it from link.local.env, which is not published. Without it the link is off.
const HOST: &str = match option_env!("TALK_LINK_SSH") {
    Some(h) => h,
    None => "",
};
const IP: &str = match option_env!("TALK_LINK_IP") {
    Some(i) => i,
    None => "",
};
const PORT: u16 = match option_env!("TALK_LINK_TEST_PORT") {
    Some(_) => 47933,
    None => 47932,
};
const MAX_SECONDS: u32 = 1800;
const MAX_TEXT: usize = 3900;

type Res<T> = Result<T, String>;

fn e<E: std::fmt::Debug>(x: E) -> String {
    format!("{x:?}")
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

fn ssh(command: &str) -> Res<String> {
    if HOST.is_empty() || IP.is_empty() {
        return Err("The test link is not set up in this build".into());
    }
    let out = Command::new("/usr/bin/ssh")
        .args(["-o", "BatchMode=yes", "-o", "ConnectTimeout=8", HOST, command])
        .stdin(Stdio::null())
        .output()
        .map_err(|_| "Could not start SSH".to_string())?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err("spark-a could not be reached over Tailscale".into())
    }
}

fn scp(from: &str, to: &str) -> bool {
    Command::new("/usr/bin/scp")
        .args(["-q", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", from, to])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Temporary folders on both machines. Dropping this removes them.
struct Session {
    local: PathBuf,
    remote: String,
    created: bool,
}

impl Session {
    fn new() -> Res<Self> {
        let id: [u8; 8] = vault::random_bytes()?;
        let local = std::env::temp_dir().join(format!("talk-link-{}", hex(&id)));
        fs::DirBuilder::new().mode(0o700).create(&local).map_err(e)?;
        Ok(Self { local, remote: format!(".talk-link-app-{}", hex(&id)), created: false })
    }

    fn push(&self, name: &str) -> Res<()> {
        let from = self.local.join(name);
        let to = format!("{HOST}:{}/{name}.part", self.remote);
        if !scp(&from.to_string_lossy(), &to) {
            return Err("Could not copy test files to spark-a".into());
        }
        ssh(&format!("mv ~/{0}/{1}.part ~/{0}/{1}", self.remote, name)).map(|_| ())
    }

    fn fetch(&self, name: &str) -> Res<Vec<u8>> {
        let to = self.local.join(format!("{name}.part"));
        let from = format!("{HOST}:{}/{name}", self.remote);
        for _ in 0..60 {
            if scp(&from, &to.to_string_lossy()) {
                let data = fs::read(&to).map_err(e)?;
                if !data.is_empty() {
                    let _ = fs::remove_file(&to);
                    return Ok(data);
                }
            }
            thread::sleep(Duration::from_millis(250));
        }
        Err("spark-a did not respond in time".into())
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if self.created {
            let _ = ssh(&format!("touch ~/{0}/stop 2>/dev/null; sleep 1.2; rm -rf ~/{0}", self.remote));
        }
        let _ = fs::remove_dir_all(&self.local);
    }
}

fn companion() -> Res<PathBuf> {
    let exe = std::env::current_exe().map_err(e)?;
    if let Some(contents) = exe.parent().and_then(Path::parent) {
        let bundled = contents.join("Resources/talk-node-linux-arm64");
        if bundled.exists() {
            return Ok(bundled);
        }
    }
    let built = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../target/spark/talk-node"));
    if built.exists() { Ok(built) } else { Err("The spark-a companion program is missing".into()) }
}

struct Msg {
    from: &'static str,
    text: String,
    at: u64,
}

pub struct Link {
    session: Session,
    client: Client,
    conn: Conn,
    tls: ClientTls,
    card: Vec<u8>,
    spark_code: String,
    mac_code: String,
    connected: bool,
    messages: Vec<Msg>,
}

impl Link {
    pub fn start() -> Res<Self> {
        let binary = companion()?;
        ssh(&format!("ss -ltnH | grep -q ':{PORT} ' && exit 9; true"))
            .map_err(|_| "spark-a is unavailable or a link is already running".to_string())?;
        let mut session = Session::new()?;
        let dir = session.local.clone();

        let mut pki = TestPki::for_names(&[IP])?;
        let tls = pki.issue("mac")?;
        tls.save(&dir, "mac")?;
        pki.issue("spark")?.save(&dir, "spark")?;
        fs::write(dir.join("server.crt"), &pki.server_cert).map_err(e)?;
        talk_prototype::pki::write_private(&dir.join("server.key"), &pki.server_key)?;
        fs::write(dir.join("accounts.txt"), "mac\nspark\n").map_err(e)?;

        ssh(&format!("umask 077; mkdir ~/{}", session.remote))?;
        session.created = true;
        let target = format!("{HOST}:{}/", session.remote);
        let mut ok = scp(&binary.to_string_lossy(), &format!("{target}talk-node"));
        for f in ["ca.der", "server.crt", "server.key", "mac.crt", "spark.crt", "spark.key", "accounts.txt"] {
            ok = ok && scp(&dir.join(f).to_string_lossy(), &target);
        }
        if !ok {
            return Err("Could not copy test files to spark-a".into());
        }
        // The relay stops at the time limit and then deletes the folder, even if this app crashes.
        let r = &session.remote;
        ssh(&format!(
            "cd ~/{r} && chmod 600 *.key && chmod 700 talk-node && \
             (nohup sh -c './talk-node relay \"$PWD\" {IP} {PORT} {MAX_SECONDS} > relay.log 2>&1; touch stop; sleep 1; cd; rm -rf \"$0\"' \"$HOME/{r}\" </dev/null >/dev/null 2>&1 &) ; \
             (nohup ./talk-node device \"$HOME/{r}\" {IP} {PORT} {MAX_SECONDS} </dev/null >device.log 2>&1 &) ; true"
        ))?;

        let host = IP.parse().map_err(e)?;
        let mut conn = None;
        for _ in 0..40 {
            if let Ok(c) = Conn::connect_host(host, PORT, &tls) {
                conn = Some(c);
                break;
            }
            thread::sleep(Duration::from_millis(150));
        }
        let conn = conn.ok_or("The private relay did not start")?;

        let client = Client::new("mac")?;
        let card = session.fetch("spark.card")?;
        fs::write(dir.join("mac.card"), client.identity_card()).map_err(e)?;
        session.push("mac.card")?;
        let spark_code = String::from_utf8(session.fetch("spark.code")?).map_err(e)?;
        let mac_code = client.safety_code(&card)?;
        Ok(Self { session, client, conn, tls, card, spark_code, mac_code, connected: false, messages: Vec::new() })
    }

    /// Runs after the person has compared the two safety codes.
    pub fn confirm(&mut self) -> Res<()> {
        if self.connected {
            return Ok(());
        }
        // The relay may have closed this connection while the person compared the codes.
        self.reconnect()?;
        self.client.trust_contact(&self.card, &self.spark_code)?;
        fs::write(self.session.local.join("mac.code"), self.mac_code.as_bytes()).map_err(e)?;
        self.session.push("mac.code")?;
        let package = self.conn.get("kp/spark").map_err(|_| "spark-a did not finish joining".to_string())?;
        let id: [u8; 12] = vault::random_bytes()?;
        self.client.create_group(&id)?;
        let welcome = commit_with_retry(&mut self.client, &mut self.conn, |c| {
            let (commit, welcome) = c.begin_add(&package)?;
            Ok((commit, Some(welcome)))
        })?
        .ok_or("no invitation produced")?;
        self.conn.put("welcome/spark", &welcome).map_err(e)?;
        self.connected = true;
        Ok(())
    }

    fn reconnect(&mut self) -> Res<()> {
        self.conn = Conn::connect_host(IP.parse().map_err(e)?, PORT, &self.tls)
            .map_err(|_| "The link to spark-a was lost".to_string())?;
        Ok(())
    }

    pub fn send(&mut self, text: &str) -> Res<()> {
        let text = text.trim();
        if !self.connected {
            return Err("spark-a is not connected".into());
        }
        if text.is_empty() || text.chars().count() > MAX_TEXT {
            return Err(format!("Message must be 1 to {MAX_TEXT} characters"));
        }
        self.poll()?;
        let sealed = self.client.send(text)?;
        if self.conn.put("in/spark", &sealed).is_err() {
            self.reconnect()?;
            self.conn.put("in/spark", &sealed).map_err(|_| "Message could not be delivered".to_string())?;
        }
        self.messages.push(Msg { from: "mac", text: text.to_string(), at: now() });
        Ok(())
    }

    pub fn poll(&mut self) -> Res<()> {
        if !self.connected {
            return Ok(());
        }
        let texts = match poll_texts(&mut self.client, &mut self.conn, "in/mac") {
            Ok(t) => t,
            Err(_) => {
                self.reconnect()?;
                poll_texts(&mut self.client, &mut self.conn, "in/mac")?
            }
        };
        for (sender, text) in texts {
            if sender == "spark" {
                self.messages.push(Msg { from: "spark", text, at: now() });
            }
        }
        Ok(())
    }

    pub fn view(&self) -> Res<Value> {
        let msgs: Vec<Value> = self.messages.iter()
            .map(|m| json!({ "from": m.from, "text": m.text, "at": m.at })).collect();
        let check = if self.connected { hex(&self.client.group_check_code()?[..6]) } else { String::new() };
        Ok(json!({
            "stage": if self.connected { "connected" } else { "verify" },
            "macCode": self.mac_code,
            "sparkCode": self.spark_code,
            "transport": self.conn.key_exchange(),
            "check": check,
            "messages": msgs,
        }))
    }
}
