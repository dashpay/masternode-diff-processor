#!/bin/bash
echo "MacOS runner: codesigning $1"
identity=$(security find-identity -p codesigning -v | grep -oE "Apple Development: (.*?) \(M62AAKG43G\)" -m 1)
codesign --force --sign "$identity" --options runtime --timestamp --entitlements dash-spv.entitlements "$1";
echo "MacOS runner: verifying $1"
codesign --verify --verbose=2 "$1"
echo "MacOS runner: exec target....."
exec "$@"
