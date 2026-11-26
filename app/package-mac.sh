#!/bin/bash
# Builds an unsigned local test copy of Talk for Apple silicon Macs.
set -euo pipefail
cd "$(dirname "$0")"
export RUSTUP_HOME="$PWD/../.toolchain/rustup" CARGO_HOME="$PWD/../.toolchain/cargo" PATH="$PWD/../.toolchain/cargo/bin:$PATH"
# Private test-machine address for the spark-a link; the file is not published.
if [ -f link.local.env ]; then set -a; . ./link.local.env; set +a; fi
cargo build --release --bin Talk
OUT="../../deliverables/apps/desktop/talk"
APP="$OUT/Talk.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp target/release/Talk "$APP/Contents/MacOS/Talk"
cp icons/Talk.icns "$APP/Contents/Resources/Talk.icns"
cp ../target/spark/talk-node "$APP/Contents/Resources/talk-node-linux-arm64"
cat > "$APP/Contents/Info.plist" <<'P'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleName</key><string>Talk</string>
<key>CFBundleDisplayName</key><string>Talk</string>
<key>CFBundleIdentifier</key><string>com.topologixlabs.talk.localtest</string>
<key>CFBundleVersion</key><string>0.1.0</string>
<key>CFBundleShortVersionString</key><string>0.1.0</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleExecutable</key><string>Talk</string>
<key>CFBundleIconFile</key><string>Talk</string>
<key>LSMinimumSystemVersion</key><string>12.0</string>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
P
codesign --force --sign - "$APP"
codesign --verify "$APP"
echo "$APP"
