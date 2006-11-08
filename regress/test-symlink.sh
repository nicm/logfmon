#!/bin/sh
# $Id$

# Sleep time
TIME=3

# Create the config file
cat <<EOF >test-symlink.conf
set mailcmd ""
set logregexp "(.*)"
file "test-symlink.link" tag test
match in test ".*" ignore
EOF

# Create the log file
ln -sf test-symlink.file test-symlink.link || exit 1
touch test-symlink.file || exit 1

# Start logfmon
../logfmon -d -f test-symlink.conf -c '' -p '' >test-symlink.out 2>&1 &

# Initial test
echo -n .; sleep $TIME
echo test-1 >test-symlink.file
echo -n .; sleep $TIME
echo test-2 >>test-symlink.file
echo -n .; sleep $TIME

# Test remove
rm test-symlink.file || exit 1
echo -n .; sleep $TIME
echo test-3 >test-symlink.file
echo -n .; sleep $TIME
echo test-4 >>test-symlink.file
echo -n .; sleep $TIME

# Test move
mv test-symlink.file test-symlink.moved || exit 1
echo -n .; sleep $TIME
echo test-5 >test-symlink.file
echo -n .; sleep $TIME
echo test-6 >>test-symlink.file
echo -n .; sleep $TIME

# Kill logfmon
echo
kill %1

# Cat the output
cat test-symlink.out || exit 1

# Clean up
rm -f test-symlink.conf test-symlink.out test-symlink.file test-symlink.link test-symlink.moved
