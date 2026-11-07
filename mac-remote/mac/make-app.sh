#!/bin/bash
# Builds MacRemote.app (the only thing that gets Accessibility permission) and its
# start-at-login file. Rebuilding changes the app's signature, so macOS asks for the
# permission again.
set -euo pipefail
cd "$(dirname "$0")"
APP=MacRemote.app; mkdir -p "$APP/Contents/MacOS" ~/.mac-remote
clang -O2 -o "$APP/Contents/MacOS/MacRemote" launcher.c \
  -DSCRIPT="\"$PWD/remote.py\"" -DLOG="\"$HOME/.mac-remote/log\""
cat > "$APP/Contents/Info.plist" <<P
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleName</key><string>Mac Remote</string>
  <key>CFBundleIdentifier</key><string>com.rohan.macremote</string>
  <key>CFBundleExecutable</key><string>MacRemote</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>LSUIElement</key><true/>
</dict></plist>
P
codesign --force -s - "$APP"
cat > local.mac-remote.plist <<P
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>local.mac-remote</string>
  <key>ProgramArguments</key><array><string>$PWD/$APP/Contents/MacOS/MacRemote</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict></plist>
P
echo "Built $APP. Start at login with:"
echo "  cp $PWD/local.mac-remote.plist ~/Library/LaunchAgents/ && launchctl bootstrap gui/\$(id -u) ~/Library/LaunchAgents/local.mac-remote.plist"
