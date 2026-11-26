//! Ordering and recovery over the relay. The relay accepts one commit per epoch;
//! clients that lose the race discard their change, catch up, and retry.

use crate::{err, relay::Conn, Client, Event, Res};
use std::{thread, time::Duration};

const MAX_RETRIES: usize = 64;

/// Applies missed group changes, stopping at `target` if given. Returns how many.
pub fn sync_to(c: &mut Client, n: &mut Conn, target: Option<u64>) -> Res<usize> {
    let log = c.log_name()?;
    let mut applied = 0;
    'epochs: while c.is_active() {
        let epoch = c.epoch()?;
        if target.is_some_and(|t| epoch >= t) { break; }
        let mut index = 0;
        loop {
            let Some(candidate) = n.fetch_commit(&log, epoch, index).map_err(err)? else { break 'epochs };
            if c.apply_commit(&candidate).is_ok() {
                applied += 1;
                continue 'epochs;
            }
            index += 1;
        }
    }
    Ok(applied)
}

/// Applies every group change this client has missed.
pub fn sync(c: &mut Client, n: &mut Conn) -> Res<usize> {
    sync_to(c, n, None)
}

/// Runs a group change until it is the first valid one for its epoch.
pub fn commit_with_retry<F>(c: &mut Client, n: &mut Conn, mut op: F) -> Res<Option<Vec<u8>>>
where F: FnMut(&mut Client) -> Res<(Vec<u8>, Option<Vec<u8>>)> {
    let log = c.log_name()?;
    for attempt in 0..MAX_RETRIES {
        sync(c, n)?;
        let epoch = c.epoch()?;
        let (commit, welcome) = op(c)?;
        match n.submit_commit(&log, epoch, &commit) {
            Ok(Some(position)) => {
                let mut lost = false;
                for i in 0..position {
                    if let Some(earlier) = n.fetch_commit(&log, epoch, i).map_err(err)? {
                        if c.apply_commit(&earlier).is_ok() { lost = true; break; }
                    }
                }
                if !lost {
                    c.confirm_commit()?;
                    return Ok(welcome);
                }
                let _ = c.abort_commit();
            }
            Ok(None) => c.abort_commit()?,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                c.abort_commit()?;
                thread::sleep(Duration::from_millis(20));
            }
            Err(e) => { c.abort_commit()?; return Err(err(e)); }
        }
        thread::sleep(Duration::from_millis(1 + (attempt as u64 % 8)));
    }
    Err("could not complete the group change".into())
}

/// Joins from a welcome. If it is damaged, asks the inviter for a fresh one, up to 3 tries.
pub fn join_with_recovery(c: &mut Client, n: &mut Conn, inviter: &str) -> Res<()> {
    let mailbox = format!("welcome/{}", c.name);
    for _ in 0..3 {
        let welcome = n.get(&mailbox).map_err(err)?;
        if c.join(&welcome).is_ok() { return Ok(()); }
        n.put(&format!("reinvite/{inviter}"), &c.key_package()?).map_err(err)?;
    }
    Err("invitation failed three times; the relay may be interfering".into())
}

/// Handles re-invite requests. Requests that fail the checks are dropped.
pub fn serve_reinvites(c: &mut Client, n: &mut Conn) -> Res<usize> {
    let mailbox = format!("reinvite/{}", c.name);
    let mut served = 0;
    while let Some(package) = n.try_get(&mailbox).map_err(err)? {
        let Ok(name) = c.accept_reinvite(&package) else { continue };
        let welcome = commit_with_retry(c, n, |c| {
            let (commit, welcome) = c.begin_swap(&name, &package)?;
            Ok((commit, Some(welcome)))
        })?.ok_or("no welcome produced")?;
        n.put(&format!("welcome/{name}"), &welcome).map_err(err)?;
        served += 1;
    }
    Ok(served)
}

/// Handles one queued item. Damaged or forged items are dropped without stopping delivery.
fn take_item(c: &mut Client, n: &mut Conn, item: &[u8]) -> Res<Option<(String, String)>> {
    let Ok(epoch) = Client::message_epoch(item) else { return Ok(None) };
    if epoch > c.epoch()? { sync_to(c, n, Some(epoch))?; }
    if let Ok(Some(Event::Text { sender, text })) = c.receive_or_hold(item) {
        return Ok(Some((sender, text)));
    }
    Ok(None)
}

/// Returns every text currently available, without waiting.
pub fn poll_texts(c: &mut Client, n: &mut Conn, mailbox: &str) -> Res<Vec<(String, String)>> {
    let log = c.log_name()?;
    let mut out = Vec::new();
    let keep = |events: Vec<Event>, out: &mut Vec<(String, String)>| {
        for event in events {
            if let Event::Text { sender, text } = event { out.push((sender, text)); }
        }
    };
    keep(c.drain_held(), &mut out);
    loop {
        if let Some(m) = n.try_get(mailbox).map_err(err)? {
            if let Some(found) = take_item(c, n, &m)? { out.push(found); }
            keep(c.drain_held(), &mut out);
            continue;
        }
        if !c.is_active() { break; }
        let epoch = c.epoch()?;
        if n.fetch_commit(&log, epoch, 0).map_err(err)?.is_none() { break; }
        if let Some(m) = n.try_get(mailbox).map_err(err)? {
            if let Some(found) = take_item(c, n, &m)? { out.push(found); }
            continue;
        }
        if sync_to(c, n, Some(epoch + 1))? == 0 { break; }
        keep(c.drain_held(), &mut out);
    }
    Ok(out)
}

/// Returns the next text. Each group change deletes the previous epoch's keys, so the
/// mailbox is checked again after a change becomes visible and before it is applied.
pub fn next_text(c: &mut Client, n: &mut Conn, mailbox: &str) -> Res<(String, String)> {
    let log = c.log_name()?;
    for _ in 0..6000 {
        for event in c.drain_held() {
            if let Event::Text { sender, text } = event { return Ok((sender, text)); }
        }
        if let Some(m) = n.try_get(mailbox).map_err(err)? {
            if let Some(found) = take_item(c, n, &m)? { return Ok(found); }
            continue;
        }
        let epoch = c.epoch()?;
        if c.is_active() && n.fetch_commit(&log, epoch, 0).map_err(err)?.is_some() {
            if let Some(m) = n.try_get(mailbox).map_err(err)? {
                if let Some(found) = take_item(c, n, &m)? { return Ok(found); }
                continue;
            }
            if sync_to(c, n, Some(epoch + 1))? > 0 { continue; }
        }
        thread::sleep(Duration::from_millis(5));
    }
    Err("timed out waiting for a message".into())
}
