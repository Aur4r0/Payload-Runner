#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BUILD_DIR="$ROOT_DIR/build"
SOURCES_FILE="$BUILD_DIR/sources.txt"
JAR_FILE="$BUILD_DIR/payload-runner-burp.jar"

mkdir -p "$BUILD_DIR"
CLASSES_DIR=$(mktemp -d "$BUILD_DIR/classes.XXXXXX")

find "$ROOT_DIR/src/compileOnly/java" "$ROOT_DIR/src/main/java" -name '*.java' | sort > "$SOURCES_FILE"

javac --release 8 -Xlint:-options -encoding UTF-8 -d "$CLASSES_DIR" @"$SOURCES_FILE"

(
  cd "$CLASSES_DIR"
  jar cf "$JAR_FILE" com burp/BurpExtender.class
)

if [ -d "$ROOT_DIR/src/main/resources" ]; then
  (
    cd "$ROOT_DIR/src/main/resources"
    jar uf "$JAR_FILE" .
  )
fi

echo "Built $JAR_FILE"
