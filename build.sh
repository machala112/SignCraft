#!/bin/bash
# Build SignCraft on a Mac (or cloud Mac) with Xcode installed.
# Produces SignCraft-unsigned.ipa in this directory.
set -e
cd "$(dirname "$0")"

echo "==> Resolving Swift packages (needs internet, one-time)…"
xcodebuild -resolvePackageDependencies \
  -project SignCraft.xcodeproj \
  -scheme SignCraft

echo "==> Building (Release, unsigned)…"
xcodebuild \
  -project SignCraft.xcodeproj \
  -scheme SignCraft \
  -configuration Release \
  -sdk iphoneos \
  -derivedDataPath ./build \
  CODE_SIGN_IDENTITY="" \
  CODE_SIGNING_REQUIRED=NO \
  CODE_SIGNING_ALLOWED=NO \
  build

APP=$(find ./build/Build/Products/Release-iphoneos -maxdepth 1 -name "*.app" | head -1)
if [ -z "$APP" ]; then
  echo "ERROR: .app not found under ./build/Build/Products/Release-iphoneos"
  exit 1
fi
echo "==> Packaging $APP"

rm -rf Payload SignCraft-unsigned.ipa
mkdir Payload
cp -R "$APP" Payload/
zip -qr SignCraft-unsigned.ipa Payload
rm -rf Payload

echo "==> Done: $(pwd)/SignCraft-unsigned.ipa"
ls -lh SignCraft-unsigned.ipa
