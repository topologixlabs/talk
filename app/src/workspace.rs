//! The local test workspace: three fictional people on one machine, each with their own
//! keys and chats, talking through the encrypted loopback relay.

pub mod link;
#[cfg(feature = "desktop")]
mod app_main;
#[cfg(feature = "desktop")]
pub use app_main::run;

use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use talk_prototype::{
    pki::{ClientTls, TestPki},
    relay::{Conn, Relay},
    sync::{commit_with_retry, sync, sync_to},
    vault, Client, Event,
};
use zeroize::Zeroizing;

pub const PEOPLE: [&str; 3] = ["alice", "bob", "carol"];
const MIN_PASSPHRASE: usize = 12;
const MAX_TEXT: usize = 4000;
const MAX_TITLE: usize = 60;

type Res<T> = Result<T, String>;

fn e<E: std::fmt::Debug>(x: E) -> String {
    format!("{x:?}")
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Res<Vec<u8>> {
    if s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid chat".into());
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(e)).collect()
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

struct Msg {
    from: String,
    text: String,
    at: u64,
}

struct Chat {
    title: String,
    client: Client,
    messages: Vec<Msg>,
    left: bool,
}

struct Person {
    name: String,
    base: Client,
    conn: Conn,
    tls: ClientTls,
    chats: BTreeMap<String, Chat>,
}

struct Workspace {
    people: Vec<Person>,
    relay: Relay,
    key: Zeroizing<[u8; 32]>,
    salt: [u8; 16],
    path: PathBuf,
}

// ---------- Saved format ----------

fn put(w: &mut Vec<u8>, b: &[u8]) {
    w.extend((b.len() as u32).to_be_bytes());
    w.extend(b);
}

fn put_n(w: &mut Vec<u8>, n: usize) {
    put(w, &(n as u64).to_be_bytes());
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn bytes(&mut self) -> Res<&'a [u8]> {
        let bad = || "damaged workspace".to_string();
        let n = u32::from_be_bytes(self.0.get(..4).ok_or_else(bad)?.try_into().map_err(e)?) as usize;
        let v = self.0.get(4..4 + n).ok_or_else(bad)?;
        self.0 = &self.0[4 + n..];
        Ok(v)
    }
    fn text(&mut self) -> Res<String> {
        String::from_utf8(self.bytes()?.to_vec()).map_err(e)
    }
    fn n(&mut self) -> Res<u64> {
        Ok(u64::from_be_bytes(self.bytes()?.try_into().map_err(e)?))
    }
}

impl Workspace {
    fn connect_all(states: Vec<(Client, BTreeMap<String, Chat>)>, key: Zeroizing<[u8; 32]>, salt: [u8; 16], path: PathBuf) -> Res<Self> {
        // Login certificates exist only while the workspace is open.
        let mut pki = TestPki::new()?;
        let mut logins = Vec::new();
        for (c, _) in &states {
            logins.push(pki.issue(&c.name)?);
        }
        let relay = Relay::start(&pki)?;
        let mut people = Vec::new();
        for ((base, chats), tls) in states.into_iter().zip(logins) {
            let conn = Conn::connect(relay.port, &tls)?;
            people.push(Person { name: base.name.clone(), base, conn, tls, chats });
        }
        Ok(Self { people, relay, key, salt, path })
    }

    fn create(path: PathBuf, passphrase: &str) -> Res<Self> {
        let salt: [u8; 16] = vault::random_bytes()?;
        let key = vault::derive_key(passphrase, &salt)?;
        let mut states = Vec::new();
        for name in PEOPLE {
            states.push((Client::new(name)?, BTreeMap::new()));
        }
        let w = Self::connect_all(states, key, salt, path)?;
        w.save()?;
        Ok(w)
    }

    fn open(path: PathBuf, passphrase: &str) -> Res<Self> {
        let (key, salt, plain) = vault::open_file(&path, passphrase)?;
        let mut r = Reader(&plain);
        let mut states = Vec::new();
        for _ in 0..r.n()? {
            let base = Client::import_state(r.bytes()?)?;
            let mut chats = BTreeMap::new();
            for _ in 0..r.n()? {
                let id = r.text()?;
                let title = r.text()?;
                let left = r.n()? == 1;
                let client = Client::import_state(r.bytes()?)?;
                let mut messages = Vec::new();
                for _ in 0..r.n()? {
                    let from = r.text()?;
                    let text = r.text()?;
                    let at = r.n()?;
                    messages.push(Msg { from, text, at });
                }
                chats.insert(id, Chat { title, client, messages, left });
            }
            states.push((base, chats));
        }
        Self::connect_all(states, key, salt, path)
    }

    fn save(&self) -> Res<()> {
        let mut w = Zeroizing::new(Vec::new());
        put_n(&mut w, self.people.len());
        for p in &self.people {
            put(&mut w, &p.base.export_state()?);
            put_n(&mut w, p.chats.len());
            for (id, c) in &p.chats {
                put(&mut w, id.as_bytes());
                put(&mut w, c.title.as_bytes());
                put_n(&mut w, usize::from(c.left));
                put(&mut w, &c.client.export_state()?);
                put_n(&mut w, c.messages.len());
                for m in &c.messages {
                    put(&mut w, m.from.as_bytes());
                    put(&mut w, m.text.as_bytes());
                    put_n(&mut w, m.at as usize);
                }
            }
        }
        vault::seal_file(&self.path, &self.key, &self.salt, &w)
    }

    /// The relay closes idle connections, so any that have gone quiet are reopened.
    fn keep_connected(&mut self) -> Res<()> {
        let port = self.relay.port;
        for p in &mut self.people {
            if p.conn.fetch_commit("log/00", 0, 0).is_err() {
                p.conn = Conn::connect(port, &p.tls)?;
            }
        }
        Ok(())
    }

    fn idx(&self, name: &str) -> Res<usize> {
        self.people.iter().position(|p| p.name == name).ok_or_else(|| "unknown person".to_string())
    }

    /// Delivers everything queued. Messages are read before later group changes apply.
    fn pump(&mut self) -> Res<()> {
        for p in &mut self.people {
            let mailbox = format!("in/{}", p.name);
            while let Some(m) = p.conn.try_get(&mailbox).map_err(e)? {
                let Ok(group) = Client::message_group(&m) else { continue };
                let Some(chat) = p.chats.get_mut(&hex(&group)) else { continue };
                if chat.left {
                    continue;
                }
                if let Ok(epoch) = Client::message_epoch(&m) {
                    if epoch > chat.client.epoch()? {
                        sync_to(&mut chat.client, &mut p.conn, Some(epoch))?;
                    }
                }
                if chat.client.is_active() {
                    if let Ok(Some(Event::Text { sender, text })) = chat.client.receive_or_hold(&m) {
                        chat.messages.push(Msg { from: sender, text, at: now() });
                    }
                }
            }
            for chat in p.chats.values_mut().filter(|c| !c.left) {
                sync(&mut chat.client, &mut p.conn)?;
                for ev in chat.client.drain_held() {
                    if let Event::Text { sender, text } = ev {
                        chat.messages.push(Msg { from: sender, text, at: now() });
                    }
                }
                if !chat.client.is_active() {
                    chat.left = true;
                }
            }
        }
        Ok(())
    }

    fn require_verified(&self, group: &[String]) -> Res<()> {
        for a in group {
            for b in group {
                if a != b && !self.people[self.idx(a)?].base.is_verified(b) {
                    return Err(format!("{} has not verified {} yet", cap(a), cap(b)));
                }
            }
        }
        Ok(())
    }

    fn invite(&mut self, actor: usize, id: &str, member: usize) -> Res<()> {
        let name = self.people[member].name.clone();
        let mut client = self.people[member].base.for_chat()?;
        let package = client.key_package()?;
        let actor_person = &mut self.people[actor];
        let chat = actor_person.chats.get_mut(id).ok_or("no such chat")?;
        let welcome = commit_with_retry(&mut chat.client, &mut actor_person.conn, |c| {
            let (commit, welcome) = c.begin_add(&package)?;
            Ok((commit, Some(welcome)))
        })?
        .ok_or("no invitation produced")?;
        let title = chat.title.clone();
        client.join(&welcome)?;
        self.people[member].chats.insert(id.to_string(), Chat { title, client, messages: Vec::new(), left: false });
        let _ = name;
        self.pump()
    }

    fn create_chat(&mut self, actor: &str, title: &str, members: &[String]) -> Res<String> {
        let title = title.trim();
        if title.is_empty() || title.chars().count() > MAX_TITLE {
            return Err(format!("Chat name must be 1 to {MAX_TITLE} characters"));
        }
        let a = self.idx(actor)?;
        let mut everyone = vec![actor.to_string()];
        for m in members {
            self.idx(m)?;
            if !everyone.contains(m) {
                everyone.push(m.clone());
            }
        }
        if everyone.len() < 2 {
            return Err("Choose at least one other person".into());
        }
        self.require_verified(&everyone)?;
        let raw: [u8; 12] = vault::random_bytes()?;
        let id = hex(&raw);
        let mut client = self.people[a].base.for_chat()?;
        client.create_group(&raw)?;
        self.people[a].chats.insert(id.clone(), Chat { title: title.to_string(), client, messages: Vec::new(), left: false });
        for m in &everyone[1..] {
            let i = self.idx(m)?;
            self.invite(a, &id, i)?;
        }
        Ok(id)
    }

    fn active_chat(&mut self, person: usize, id: &str) -> Res<&mut Chat> {
        let chat = self.people[person].chats.get_mut(id).ok_or("no such chat")?;
        if chat.left {
            return Err("You are no longer in this chat".into());
        }
        Ok(chat)
    }

    fn send(&mut self, actor: &str, id: &str, text: &str) -> Res<()> {
        let text = text.trim();
        if text.is_empty() || text.chars().count() > MAX_TEXT {
            return Err(format!("Message must be 1 to {MAX_TEXT} characters"));
        }
        let a = self.idx(actor)?;
        self.pump()?;
        let chat = self.active_chat(a, id)?;
        let sealed = chat.client.send(text)?;
        let members = chat.client.member_names();
        chat.messages.push(Msg { from: actor.to_string(), text: text.to_string(), at: now() });
        for m in members.iter().filter(|m| *m != actor) {
            self.people[a].conn.put(&format!("in/{m}"), &sealed).map_err(e)?;
        }
        self.pump()
    }

    fn add_member(&mut self, actor: &str, id: &str, member: &str) -> Res<()> {
        let a = self.idx(actor)?;
        let m = self.idx(member)?;
        self.pump()?;
        let mut group = self.active_chat(a, id)?.client.member_names();
        if group.iter().any(|x| x == member) {
            return Err("Already in this chat".into());
        }
        if self.people[m].chats.get(id).is_some_and(|c| !c.left) {
            return Err("Already in this chat".into());
        }
        group.push(member.to_string());
        self.require_verified(&group)?;
        // A person who left and returns gets a new chat state and sees only new messages.
        let history = self.people[m].chats.remove(id).map(|c| c.messages);
        self.invite(a, id, m)?;
        if let (Some(old), Some(chat)) = (history, self.people[m].chats.get_mut(id)) {
            chat.messages.splice(0..0, old);
        }
        Ok(())
    }

    fn remove_member(&mut self, actor: &str, id: &str, member: &str) -> Res<()> {
        if actor == member {
            return Err("You cannot remove yourself in this test".into());
        }
        let a = self.idx(actor)?;
        self.pump()?;
        self.active_chat(a, id)?;
        let p = &mut self.people[a];
        let chat = p.chats.get_mut(id).ok_or("no such chat")?;
        commit_with_retry(&mut chat.client, &mut p.conn, |c| Ok((c.begin_remove(member)?, None)))?;
        self.pump()
    }

    fn rotate(&mut self, actor: &str, id: &str) -> Res<()> {
        let a = self.idx(actor)?;
        self.pump()?;
        self.active_chat(a, id)?;
        let p = &mut self.people[a];
        let chat = p.chats.get_mut(id).ok_or("no such chat")?;
        commit_with_retry(&mut chat.client, &mut p.conn, |c| Ok((c.begin_update()?, None)))?;
        self.pump()
    }

    /// Alters one sealed message inside the relay and reports what the recipient did.
    fn tamper_test(&mut self, actor: &str, id: &str) -> Res<Value> {
        let a = self.idx(actor)?;
        self.pump()?;
        let chat = self.active_chat(a, id)?;
        let other = chat.client.member_names().into_iter().find(|m| m != actor).ok_or("No one else is in this chat")?;
        let sealed = chat.client.send("FICTIONAL tamper test")?;
        let mailbox = format!("in/{other}");
        self.people[a].conn.put(&mailbox, &sealed).map_err(e)?;
        if !self.relay.tamper_next(&mailbox, sealed.len() - 1) {
            return Err("Tamper test could not run".into());
        }
        let o = self.idx(&other)?;
        let p = &mut self.people[o];
        let got = p.conn.try_get(&mailbox).map_err(e)?.ok_or("Tamper test message missing")?;
        let chat = p.chats.get_mut(id).ok_or("no such chat")?;
        let rejected = chat.client.receive(&got).is_err();
        Ok(json!({ "recipient": other, "rejected": rejected }))
    }

    fn codes(&self, a: &str, b: &str) -> Res<Value> {
        let (x, y) = (&self.people[self.idx(a)?].base, &self.people[self.idx(b)?].base);
        Ok(json!({
            "a": a, "b": b,
            "codeA": x.safety_code(&y.identity_card())?,
            "codeB": y.safety_code(&x.identity_card())?,
            "verified": x.is_verified(b) && y.is_verified(a),
        }))
    }

    fn verify(&mut self, a: &str, b: &str) -> Res<()> {
        if a == b {
            return Err("Choose two different people".into());
        }
        let (i, j) = (self.idx(a)?, self.idx(b)?);
        let (card_a, card_b) = (self.people[i].base.identity_card(), self.people[j].base.identity_card());
        let (code_a, code_b) = (self.people[i].base.safety_code(&card_b)?, self.people[j].base.safety_code(&card_a)?);
        self.people[i].base.trust_contact(&card_b, &code_b)?;
        self.people[j].base.trust_contact(&card_a, &code_a)?;
        for k in [i, j] {
            let base = self.people[k].base.for_chat()?;
            for c in self.people[k].chats.values_mut() {
                c.client.copy_contacts_from(&base);
            }
        }
        Ok(())
    }

    fn view(&self, person: &str) -> Res<Value> {
        let p = &self.people[self.idx(person)?];
        let people: Vec<Value> = PEOPLE.iter().filter(|n| **n != person)
            .map(|n| json!({ "name": n, "verified": p.base.is_verified(n) })).collect();
        let mut chats: Vec<(u64, Value)> = Vec::new();
        for (id, c) in &p.chats {
            let members = if c.left { Vec::new() } else { c.client.member_names() };
            let last = c.messages.last().map_or(0, |m| m.at);
            let check = if c.left { String::new() } else { hex(&c.client.group_check_code()?[..6]) };
            let same_history = !c.left && self.people.iter().all(|o| {
                o.chats.get(id).is_none_or(|oc| oc.left || oc.client.group_check_code().ok() == c.client.group_check_code().ok())
            });
            let msgs: Vec<Value> = c.messages.iter()
                .map(|m| json!({ "from": m.from, "text": m.text, "at": m.at })).collect();
            chats.push((last, json!({
                "id": id, "title": c.title, "left": c.left, "members": members,
                "epoch": if c.left { 0 } else { c.client.epoch()? },
                "check": check, "sameHistory": same_history, "messages": msgs,
            })));
        }
        chats.sort_by(|a, b| b.0.cmp(&a.0));
        let chats: Vec<Value> = chats.into_iter().map(|x| x.1).collect();
        Ok(json!({ "person": person, "people": people, "chats": chats }))
    }
}

fn cap(s: &str) -> String {
    let mut c = s.chars();
    c.next().map_or_else(String::new, |f| f.to_uppercase().collect::<String>() + c.as_str())
}

fn s<'a>(args: &'a Value, key: &str) -> Res<&'a str> {
    args[key].as_str().ok_or_else(|| format!("missing {key}"))
}

// ---------- Share outside Talk ----------

/// Checks text before it is handed to another app.
pub fn clean_share_text(text: &str) -> Res<&str> {
    let text = text.trim();
    if text.is_empty() {
        return Err("Write a message first".into());
    }
    if text.chars().count() > MAX_TEXT {
        return Err(format!("Messages can be up to {MAX_TEXT} characters"));
    }
    Ok(text)
}

// ---------- Share to WhatsApp ----------

/// Builds a link for the installed WhatsApp app only. It deliberately avoids the web
/// link, which would put the message in browser history and send it to a website.
pub fn whatsapp_share_url(text: &str) -> Res<String> {
    let text = clean_share_text(text)?;
    let mut url = String::from("whatsapp://send?text=");
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.~".contains(&byte) {
            url.push(byte as char);
        } else {
            url.push_str(&format!("%{byte:02X}"));
        }
    }
    Ok(url)
}

// ---------- App ----------

pub struct App {
    path: PathBuf,
    open: Option<Workspace>,
    link: Option<link::Link>,
}

impl App {
    pub fn new(dir: PathBuf) -> Self {
        Self { path: dir.join("talk-test-workspace.vault"), open: None, link: None }
    }

    /// Ends the Spark link and removes its temporary files.
    pub fn shutdown(&mut self) {
        self.link = None;
    }

    fn link_command(&mut self, name: &str, args: &Value) -> Res<Value> {
        if self.open.is_none() {
            return Err("Workspace is locked".into());
        }
        match name {
            "linkStart" if self.link.is_none() => self.link = Some(link::Link::start()?),
            "linkStart" | "linkStatus" => {}
            "linkStop" => self.link = None,
            "linkConfirm" => self.link.as_mut().ok_or("spark-a is not connected")?.confirm()?,
            "linkSend" => self.link.as_mut().ok_or("spark-a is not connected")?.send(s(args, "text")?)?,
            _ => self.link.as_mut().ok_or("spark-a is not connected")?.poll()?,
        }
        match &self.link {
            Some(l) => l.view(),
            None => Ok(json!({ "stage": "off" })),
        }
    }

    fn workspace(&mut self) -> Res<&mut Workspace> {
        let w = self.open.as_mut().ok_or_else(|| "Workspace is locked".to_string())?;
        w.keep_connected()?;
        Ok(w)
    }

    fn stage(&self) -> &'static str {
        if self.open.is_some() { "open" } else if self.path.exists() { "locked" } else { "new" }
    }

    pub fn command(&mut self, name: &str, args: &Value) -> Res<Value> {
        match name {
            "status" => Ok(json!({ "stage": self.stage(), "platform": std::env::consts::OS })),
            "create" => {
                let pass = s(args, "passphrase")?;
                if pass.chars().count() < MIN_PASSPHRASE {
                    return Err(format!("Use at least {MIN_PASSPHRASE} characters"));
                }
                if self.path.exists() {
                    return Err("A workspace already exists".into());
                }
                self.open = Some(Workspace::create(self.path.clone(), pass)?);
                Ok(json!({ "stage": "open" }))
            }
            "unlock" => {
                let w = Workspace::open(self.path.clone(), s(args, "passphrase")?)
                    .map_err(|x| if x.contains("passphrase") { "Wrong passphrase".to_string() } else { x })?;
                self.open = Some(w);
                Ok(json!({ "stage": "open" }))
            }
            "linkStatus" | "linkStart" | "linkConfirm" | "linkSend" | "linkPoll" | "linkStop" => self.link_command(name, args),
            "lock" => {
                self.link = None;
                if let Some(w) = &self.open {
                    w.save()?;
                }
                self.open = None;
                Ok(json!({ "stage": "locked" }))
            }
            "reset" => {
                if s(args, "confirm")? != "RESET" {
                    return Err("Reset was not confirmed".into());
                }
                self.link = None;
                self.open = None;
                if self.path.exists() {
                    std::fs::remove_file(&self.path).map_err(e)?;
                }
                Ok(json!({ "stage": "new" }))
            }
            "view" => { let w = self.workspace()?; w.pump()?; w.view(s(args, "person")?) }
            "codes" => self.workspace()?.codes(s(args, "a")?, s(args, "b")?),
            "tamper" => {
                let w = self.workspace()?;
                let out = w.tamper_test(s(args, "person")?, s(args, "chat")?)?;
                w.save()?;
                Ok(out)
            }
            "verify" | "createChat" | "send" | "addMember" | "removeMember" | "rotate" => {
                let w = self.workspace()?;
                let out = match name {
                    "verify" => { w.verify(s(args, "a")?, s(args, "b")?)?; json!({}) }
                    "createChat" => {
                        let members: Vec<String> = args["members"].as_array().ok_or("missing members")?
                            .iter().filter_map(|v| v.as_str().map(String::from)).collect();
                        json!({ "id": w.create_chat(s(args, "person")?, s(args, "title")?, &members)? })
                    }
                    "send" => { unhex(s(args, "chat")?)?; w.send(s(args, "person")?, s(args, "chat")?, s(args, "text")?)?; json!({}) }
                    "addMember" => { w.add_member(s(args, "person")?, s(args, "chat")?, s(args, "member")?)?; json!({}) }
                    "removeMember" => { w.remove_member(s(args, "person")?, s(args, "chat")?, s(args, "member")?)?; json!({}) }
                    _ => { w.rotate(s(args, "person")?, s(args, "chat")?)?; json!({}) }
                };
                w.save()?;
                Ok(out)
            }
            _ => Err("unknown command".into()),
        }
    }
}

#[cfg(test)]
mod whatsapp_tests {
    use super::*;

    #[test]
    fn encodes_text_so_it_cannot_change_the_link() {
        let url = whatsapp_share_url("  a b&phone=1#x?\nnew  ").unwrap();
        assert_eq!(url, "whatsapp://send?text=a%20b%26phone%3D1%23x%3F%0Anew");
    }

    #[test]
    fn encodes_non_english_text_and_emoji() {
        assert_eq!(whatsapp_share_url("é😀").unwrap(), "whatsapp://send?text=%C3%A9%F0%9F%98%80");
    }

    #[test]
    fn rejects_empty_and_too_long_messages() {
        assert!(whatsapp_share_url(" \n ").is_err());
        assert!(whatsapp_share_url(&"a".repeat(MAX_TEXT)).is_ok());
        assert!(whatsapp_share_url(&"a".repeat(MAX_TEXT + 1)).is_err());
    }
}

#[cfg(test)]
mod idle_tests {
    use super::*;

    #[test]
    fn workspace_keeps_working_after_relay_idle_timeout() {
        let dir = std::env::temp_dir().join(format!("talk-idle-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut app = App::new(dir.clone());
        app.command("create", &json!({ "passphrase": "fictional idle test" })).unwrap();
        app.command("verify", &json!({ "a": "alice", "b": "bob" })).unwrap();
        let id = app.command("createChat", &json!({ "person": "alice", "title": "Idle", "members": ["bob"] })).unwrap();
        let chat = id["id"].as_str().unwrap().to_string();
        std::thread::sleep(std::time::Duration::from_secs(32));
        app.command("view", &json!({ "person": "bob" })).unwrap();
        app.command("send", &json!({ "person": "alice", "chat": chat, "text": "after idle" })).unwrap();
        let view = app.command("view", &json!({ "person": "bob" })).unwrap();
        assert_eq!(view["chats"][0]["messages"][0]["text"], "after idle");
        app.shutdown();
        std::fs::remove_dir_all(dir).unwrap();
    }
}
