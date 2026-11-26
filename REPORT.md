# Talk local prototype: test report

23 November 2026. Private test code with fictional data. Do not use it for real messages.

## Result

Talk now runs as a real, unsigned Mac test app at `deliverables/apps/desktop/talk/Talk.app`. It uses the tested encryption core with three fictional people on one Mac. All 57 core tests pass on this Mac and spark-b. The Mac app can now connect to spark-a as a second device over private Tailscale.

This does not make Talk safe for real use. It has had no independent security review or dependency scan, and spark-a is a scripted companion rather than a second person using an app.

## Two-device link (Mac and spark-a)

The final link test passed 15 of 15 runs over the private Tailscale network. Each run used a temporary relay on spark-a that listened only on its Tailscale address, and removed its test files afterwards.

- **Passed:** safety-code verification over a separate SSH channel, two-way messages, 200 encrypted round trips (about 11 ms median), tamper rejection, 10 simultaneous group changes, a Spark restart with offline catch-up, and removal of the Spark from the group.
- **Refused:** connections with no certificate, a forged certificate, or no TLS. The relay was not reachable on the home network address tested.
- **Relay view:** the relay handled sealed data and the test message text was not visible to it.
- **Bugs fixed:** the test cleanup left a temporary folder once, now removed and fixed. One of five earlier runs failed; the likely cause was a group change being applied just before a message arrived. After that ordering fix, all 15 runs passed, but the original failure's log was not kept, so the cause is not proven.
- **Limits:** both devices were scripted with fictional people on one private network. Phones, poor connections, the wider internet and more than one sender racing a group change were not tested.

## Device link in the app

Choose **Connect** beside spark-a, compare the two safety codes, and send a fictional message. spark-a decrypts it and replies automatically.

- **Checked in a real Mac window:** a connected link, an encrypted message to spark-a, and its decrypted reply.
- **Checked in a browser preview of the same interface:** connection, the safety-code gate, hostile message text, draft preservation, Disconnect, and removal of the test link's files and relay.
- **Link limits:** one link at a time, fixed to spark-a, kept in memory, and stopped by Disconnect, Lock, quitting, or after 30 minutes. Link messages are not saved.

## Share to iMessage

The chat screen has an **iMessage** button. Talk shows a warning, then asks Apple's Mac share service to open a Messages compose window. The person chooses the recipient and presses send. Talk cannot read Messages or send through it.

- **Checked in a real Mac window:** the button, warning, and Apple's share service accepting fictional text.
- **Not confirmed:** the text appearing in Messages, because the Messages window was deliberately not viewed to protect private conversations. Nothing was sent.
- **Encryption:** shared text leaves Talk's quantum-resistant encryption, and an SMS would not be end-to-end encrypted.
- **Bug fixed:** Talk's local connections dropped after 30 idle seconds, causing later actions to fail. They now reconnect, and a test covers this.

## iPhone and iPad build

Talk now builds for iPhone as a Tauri iOS app, and it opens in the iPhone simulator at its setup screen.

- **Phone layout:** one screen at a time, moving between chat list, conversation and details. In a browser preview at iPhone size, chat creation, messages, details, back navigation and screen fit all worked.
- **iPad:** the same build supports iPad. On the iPad Pro 13-inch simulator, creating a workspace, safety-code verification, creating a chat, sending a message, Bob receiving it, and unlocking after a restart all worked natively.
- **Bugs fixed on iPad:** the status bar overlapped the top of Talk, and the keyboard pushed the screen out of view. Both now behave correctly.
- **Not tested:** tapping through the iPhone simulator, because its access prompt went unanswered. Talk has not been installed on a real iPhone or iPad. That needs the device connected, Developer Mode on, and Xcode signed in to the director's Apple developer account.
- **Not available on iPhone yet:** the spark-a link, which needs SSH, and the WhatsApp and iMessage buttons, which use Mac-only services.
- **Tools installed:** Rust iPhone libraries and the Tauri build tool in the Talk project folders. Homebrew gained CocoaPods with Ruby, OpenSSL and libyaml, which the director approved. The Tauri tool also installed xcodegen and libimobiledevice by itself, which the director chose to keep.

## The Mac app

- **What it does:** verify safety codes, create chats, send messages, add and remove members, rotate keys, run a tamper test, and lock with a passphrase.
- **Checked in the real Mac window:** setup, unlock, verification, chat creation, message delivery, tamper rejection, member removal, lock and workspace deletion.
- **Checked in a browser preview of the same interface:** mismatched and wrong passphrases, a three-person chat, hostile message text shown harmlessly, re-adding a removed member, and delivery after unlock.
- **Saved data:** the workspace file is owner-only, and a search of it found none of the test message text, chat names or people's names.
- **Bug found and fixed:** native confirmation boxes are unreliable in the Mac web view, so the app now draws its own.
- **Limits:** all three people live in one app on one Mac, so this does not prove delivery between devices. The app is ad-hoc signed and not notarised, so macOS may warn when it is opened on another Mac. It is built for Apple silicon only.

## What changed

| Gap | Fix | Library doing the security work |
| --- | --- | --- |
| Anyone could claim a name | People compare a 40-digit safety code once. Unverified people and changed keys are refused | OpenMLS signatures, SHA-256 |
| Keys vanished on exit | Keys are saved in a passphrase-encrypted, owner-only file | Argon2id, ChaCha20-Poly1305 |
| Relay had no login or encryption | TLS 1.3 with hybrid X25519MLKEM768, login certificates, mailbox permissions, rate and size limits | rustls, aws-lc-rs |
| Tampered invitation blocked a join | The person automatically requests a new invitation, up to 3 times | OpenMLS |
| Simultaneous changes could split a group | The relay keeps changes in order, and clients apply the first valid one and retry if they lose | OpenMLS |

## What was tested

| Area | Tests | Examples |
| --- | --- | --- |
| Core encryption | 19 | Every byte of a message, invitation, group change and key package altered; replay; wrong keys; removed and new members |
| Identity | 7 | Swapped identity card, impersonator, changed key, unverified member in a group |
| Encrypted storage | 4 | Restart and continue, wrong passphrase, damaged file, no readable contents |
| Relay access | 11 | No TLS, no certificate, forged certificate, fake relay, reading another person's mailbox, rate limit, oversized data |
| Invitation recovery | 4 | Automatic recovery, replayed request, forged request, request cap |
| Ordering and offline | 10 | Three people changing a group at once, junk group changes, offline catch-up, relay showing members different histories |

Before the final code freeze, the full set passed 30 of 30 repeat runs on spark-b at lowest priority and 10 of 10 on spark-a. The three-process demo passed in every one of those runs. A final one-line test cleanup was then rerun once on spark-b and passed.

## Flaws found and fixed during this work

- Any logged-in user could block a group by posting a junk group change first. Clients now skip invalid changes.
- An offline member could lose messages by applying later group changes before reading them. Queued messages are now read first.

## Known limits that remain

- **Late messages can still be lost.** A message sent just as a group change lands may become unreadable, because old keys are deliberately deleted.
- **Split-history detection is manual.** Members can compare a check code, but the app does not do this automatically yet.
- **Members with different verified contacts can diverge.** One may accept a group change that another refuses. The check code reveals this, but nothing repairs it.
- **Old vault files can be restored.** Encryption stops reading or altering them, but not someone rolling a device back to an older copy.
- **A crash during a group change is not handled.** The relay allows one candidate per account per epoch, so recovery needs more work.
- **Relay data is held in memory.** Restarting the relay loses queued messages.
- **Certificates come from a private test authority.** There is no real sign-up, device enrolment or revocation.
- **Signatures and certificates are classical.** Key exchange is quantum-resistant, but authentication is not. The hybrid message suite also uses a provisional identifier.

## What was not tested

- Windows, iOS, Android, Ubuntu Touch, Intel Macs and a packaged web version. The core was run on Apple silicon Mac and Linux on ARM.
- The wider internet, poor connections, or phones. The two-device test used a private Tailscale network.
- A legitimate member attempting to forge another member's messages.
- Large groups, sustained load, and timing or other side-channel attacks.
- Dependency vulnerability scanning.
- Whether OpenMLS's May 2026 audit covered the post-quantum code or this version.

## What still blocks a private beta

1. An independent security review and a dependency scan.
2. Real invitations between people on separate devices, with recovery screens.
3. Real account enrolment, device keys held in each system's secure keychain, and revocation.
4. A durable relay on a private server, which needs the director's spending approval.
5. Fixes for late-message loss, automatic split-history detection and crash recovery.
6. Blocking and abuse reporting, which the app stores require.
7. Multi-device support, backups, media and calling.
8. The director's decisions on source publication, minimum age, and solicitor and audit quotes.

## How to rerun

On spark-b, from `~/talk-prototype`:

```bash
nice -n 19 cargo test --release
```

```bash
nice -n 19 cargo run --release
```
