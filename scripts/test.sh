#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BUILD_DIR="$ROOT_DIR/build"
SOURCES_FILE="$BUILD_DIR/test-sources.txt"

mkdir -p "$BUILD_DIR"
CLASSES_DIR=$(mktemp -d "$BUILD_DIR/test-classes.XXXXXX")

find "$ROOT_DIR/src/compileOnly/java" "$ROOT_DIR/src/main/java" "$ROOT_DIR/src/test/java" \
  -name '*.java' | sort > "$SOURCES_FILE"

javac --release 8 -Xlint:-options -encoding UTF-8 -d "$CLASSES_DIR" @"$SOURCES_FILE"
if [ -d "$ROOT_DIR/src/main/resources" ]; then
  cp -R "$ROOT_DIR/src/main/resources/." "$CLASSES_DIR/"
fi
java -Djava.awt.headless=true -cp "$CLASSES_DIR" com.vibecode.payloadrunner.SmokeTest
