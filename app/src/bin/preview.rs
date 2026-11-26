//! Test-only: serves the same interface on loopback so it can be checked in a browser.
//! It is not part of the Mac app.

use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpListener;
use talk_desktop::App;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let port = args.get(1).map_or("4177", String::as_str);
    let dir = std::env::temp_dir().join(format!("talk-preview-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp folder");
    let mut app = App::new(dir);
    let listener = TcpListener::bind(("127.0.0.1", port.parse::<u16>().expect("port"))).expect("bind");
    println!("preview on http://127.0.0.1:{port}");
    for stream in listener.incoming().flatten() {
        let mut s = stream;
        let mut buf = Vec::new();
        let mut chunk = [0u8; 8192];
        let (head_end, length) = loop {
            let Ok(n) = s.read(&mut chunk) else { break (0, 0) };
            if n == 0 { break (0, 0); }
            buf.extend(&chunk[..n]);
            if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&buf[..p]).to_ascii_lowercase();
                let len = head.lines().find_map(|l| l.strip_prefix("content-length:")).and_then(|v| v.trim().parse().ok()).unwrap_or(0);
                break (p + 4, len);
            }
        };
        if head_end == 0 { continue; }
        while buf.len() < head_end + length {
            let Ok(n) = s.read(&mut chunk) else { break };
            if n == 0 { break; }
            buf.extend(&chunk[..n]);
        }
        let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
        let path = head.split_whitespace().nth(1).unwrap_or("/").to_string();
        // Only this preview's own page may call it: refuse other websites (cross-site requests)
        // and other host names pointed at this address (DNS rebinding).
        let header = |name: &str| head.lines().find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim().eq_ignore_ascii_case(name).then(|| v.trim().to_ascii_lowercase())
        });
        let own = [format!("127.0.0.1:{port}"), format!("localhost:{port}")];
        let host_ok = header("host").is_some_and(|h| own.contains(&h));
        let origin_ok = header("origin").is_none_or(|o| own.iter().any(|h| o == format!("http://{h}")));
        if !host_ok || !origin_ok {
            let _ = write!(s, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            continue;
        }
        let (ctype, body): (&str, Vec<u8>) = match path.as_str() {
            "/" | "/index.html" => ("text/html", include_bytes!("../../ui/index.html").to_vec()),
            "/app.js" => ("text/javascript", include_bytes!("../../ui/app.js").to_vec()),
            "/style.css" => ("text/css", include_bytes!("../../ui/style.css").to_vec()),
            "/api" => {
                let req: Value = serde_json::from_slice(&buf[head_end..]).unwrap_or(Value::Null);
                let out = app.command(req["name"].as_str().unwrap_or(""), &req["args"]);
                let v = match out { Ok(v) => json!({"ok": v}), Err(e) => json!({"error": e}) };
                ("application/json", v.to_string().into_bytes())
            }
            _ => ("text/plain", b"not found".to_vec()),
        };
        let _ = write!(s, "HTTP/1.1 200 OK\r\nContent-Type: {ctype}; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n", body.len());
        let _ = s.write_all(&body);
    }
}
