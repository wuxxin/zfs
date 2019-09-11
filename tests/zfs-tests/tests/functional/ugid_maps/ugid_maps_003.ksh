#!/bin/ksh -p
. $STF_SUITE/include/libtest.shlib

ZFS_USER=$(cat /tmp/zfs-ugid-map-test-user.txt)
TEST_UID=$(cat /tmp/zfs-ugid-map-test-uid.txt)
TEST_GID=$(cat /tmp/zfs-ugid-map-test-gid.txt)
FSDIR=$(get_prop mountpoint $TESTPOOL/$TESTFS)

log_must zfs unmount $TESTPOOL/$TESTFS/both
log_must zfs set uidmap="0:100000:65536" $TESTPOOL/$TESTFS/both
log_must zfs set gidmap="0:200000:65536" $TESTPOOL/$TESTFS/both
log_must zfs mount $TESTPOOL/$TESTFS/both
log_must zfs create $TESTPOOL/$TESTFS/both.noprop
log_must zfs create $TESTPOOL/$TESTFS/both.withprop
log_must zfs snapshot $TESTPOOL/$TESTFS/both@snap

log_must zfs send $TESTPOOL/$TESTFS/both@snap | zfs recv -F $TESTPOOL/$TESTFS/both.noprop
owner=$(stat -c %u:%g "$FSDIR/both.noprop/test.txt")
[ "$owner" == "500:600" ] || \
    log_fail "UID/GID is persisted mapped: expected 500:600, got $owner"

owner=$(stat -c %u:%g "$FSDIR/both.noprop/userdir/test.txt")
[ "$owner" == "$(($TEST_UID-100000)):$(($TEST_GID-200000))" ] || \
    log_fail "UID/GID is persisted mapped: expected $(($TEST_UID-100000)):$(($TEST_GID-200000))"

log_must zfs send -p $TESTPOOL/$TESTFS/both@snap | zfs recv -F $TESTPOOL/$TESTFS/both.withprop
owner=$(stat -c %u:%g "$FSDIR/both.withprop/test.txt")
[ "$owner" == "$((500+100000)):$((600+200000))" ] || \
    log_fail "maps UIDs/GIDs in setattr: expected $((500+100000)):$((600+200000)), got $owner"

owner=$(stat -c %u:%g "$FSDIR/both.withprop/userdir")
[ "$owner" == "$TEST_UID:$TEST_GID" ] || \
    log_fail "does not map UIDs/GIDs: expected $TEST_UID:$TEST_GID, got $owner"

owner=$(stat -c %u:%g "$FSDIR/both.withprop/userdir/test.txt")
[ "$owner" == "$TEST_UID:$TEST_GID" ] || \
    log_fail "does not map UIDs/GIDs: expected $TEST_UID:$TEST_GID, got $owner"

log_pass
