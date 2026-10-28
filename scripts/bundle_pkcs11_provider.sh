#!/bin/sh
# Copy the build Python's pkcs11-provider into the freeze tree and retarget freeze libcrypto.
# Copyright (C) 2003-2026 ITRS Group Ltd. All rights reserved
set -eu

FREEZE_DIR=${1:?usage: bundle_pkcs11_provider.sh <freeze-bin-dir>}
MIN_OPENSSL_VERSION=${MIN_OPENSSL_VERSION:-3.0.7}
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
SRC_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)

version_ge() {
    # True when $1 >= $2 (dotted numeric versions).
    [ "$(printf '%s\n' "$1" "$2" | sort -V | tail -n 1)" = "$1" ]
}

FREEZE_LIB="$FREEZE_DIR/lib"
if [ ! -d "$FREEZE_LIB" ]; then
    echo "Freeze lib directory not found: $FREEZE_LIB" >&2
    exit 1
fi

LIBCRYPTO=
for cand in "$FREEZE_LIB"/libcrypto-*.so.3 "$FREEZE_LIB"/libcrypto.so.3; do
    if [ -f "$cand" ]; then
        LIBCRYPTO=$cand
        break
    fi
done
if [ -z "$LIBCRYPTO" ]; then
    echo "Freeze libcrypto.so.3 not found in $FREEZE_LIB" >&2
    exit 1
fi

OPENSSL_VERSION=$(
    strings "$LIBCRYPTO" | sed -n 's/^OpenSSL \([0-9][0-9.]*\).*/\1/p' | head -n 1
)
if [ -z "$OPENSSL_VERSION" ]; then
    echo "Could not determine OpenSSL version from $LIBCRYPTO" >&2
    exit 1
fi
if ! version_ge "$OPENSSL_VERSION" "$MIN_OPENSSL_VERSION"; then
    echo "Freeze libcrypto is OpenSSL $OPENSSL_VERSION; pkcs11-provider requires $MIN_OPENSSL_VERSION or later." >&2
    echo "Build the agent with a Python linked to OpenSSL $MIN_OPENSSL_VERSION+." >&2
    exit 1
fi

if [ -z "${OPENSSL_PREFIX:-}" ] && [ -n "${PYTHON:-}" ]; then
    OPENSSL_PREFIX=$("$PYTHON" -c 'import sys; print(sys.base_prefix)')
fi
if [ -z "${OPENSSL_PREFIX:-}" ]; then
    echo "Set PYTHON or OPENSSL_PREFIX to the prefix that contains ossl-modules/pkcs11.so." >&2
    exit 1
fi

SRC_SO=
for cand in "$OPENSSL_PREFIX/lib/ossl-modules/pkcs11.so" "$OPENSSL_PREFIX/lib64/ossl-modules/pkcs11.so"; do
    if [ -f "$cand" ]; then
        SRC_SO=$cand
        break
    fi
done
if [ -z "$SRC_SO" ]; then
    echo "pkcs11.so not found under $OPENSSL_PREFIX/lib/ossl-modules." >&2
    echo "Rebuild that Python so its prefix vendors and installs pkcs11-provider." >&2
    exit 1
fi

if ! command -v patchelf >/dev/null 2>&1; then
    echo "Missing build tool 'patchelf' (needed to retarget pkcs11.so onto freeze libcrypto)" >&2
    exit 1
fi

DEST_DIR="$FREEZE_LIB/ossl-modules"
mkdir -p "$DEST_DIR"
DEST_SO="$DEST_DIR/pkcs11.so"
cp "$SRC_SO" "$DEST_SO"

SONAME=$(basename "$LIBCRYPTO")
patchelf --set-rpath '$ORIGIN/..' "$DEST_SO"
if [ "$SONAME" != "libcrypto.so.3" ]; then
    if patchelf --print-needed "$DEST_SO" | grep -qx 'libcrypto.so.3'; then
        patchelf --replace-needed libcrypto.so.3 "$SONAME" "$DEST_SO"
    fi
fi

mkdir -p "$FREEZE_DIR/../licenses"
cp "$SRC_DIR/LICENSE_APACHE-2.0" "$FREEZE_DIR/../licenses/LICENSE_APACHE-2.0"

echo "Installed $DEST_SO from $SRC_SO (OpenSSL $OPENSSL_VERSION, NEEDED $(patchelf --print-needed "$DEST_SO" | tr '\n' ' '))"
