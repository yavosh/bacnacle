#!/bin/sh
# Select one diagnostic profile from extracted main/daily members and signed bytecode.cvd.
set -eu
if [ "$#" != 3 ]; then
    echo 'usage: select_profile_db.sh SOURCE NEW_DIRECTORY all|base|omit-section|omit-logical|omit-body|omit-whole|omit-other' >&2
    exit 2
fi
source_dir=$1
destination=$2
profile=$3
case "$profile" in
    all|base|omit-section|omit-logical|omit-body|omit-whole|omit-other) ;;
    *) echo "unknown diagnostic profile: $profile" >&2; exit 2 ;;
esac
mkdir "$destination"
for source in "$source_dir"/*; do
    case "${source##*/}" in
        main.*|daily.*|bytecode.cvd) ;;
        COPYING) continue ;;
        *) echo "unexpected database member: ${source##*/}" >&2; exit 1 ;;
    esac
    case "${source##*.}" in
        info) continue ;;
        mdb|msb|mdu|msu) family=section ;;
        ldb|ldu) family=logical ;;
        ndb|ndu) family=body ;;
        hdb|hsb|hdu|hsu) family=whole ;;
        cdb|idb|pdb|wdb) family=other ;;
        cfg|ftm|crb|ign|ign2|fp|sfp) family=fixed ;;
        cvd) [ "${source##*/}" = bytecode.cvd ] || exit 1; family=fixed ;;
        *) echo "unclassified database member: ${source##*/}" >&2; exit 1 ;;
    esac
    if [ "$family" != fixed ] && { [ "$profile" = base ] || [ "$profile" = "omit-$family" ]; }; then
        continue
    fi
    ln "$source" "$destination/"
done
