#!/bin/sh
# $Id$

# Sleep time
TIME=5

# File prefix
P=/tmp/test-symlink

# Create the config file
cat <<EOF >${P}.conf
set mailcmd ""
set logregexp "(.*)"
file "${P}.link" tag test
match in test ".*" ignore
EOF

# Create the log file
ln -sf ${P}.file ${P}.link || exit 1
touch ${P}.file || exit 1

# Start logfmon
../logfmon -d -f ${P}.conf -c '' -p '' >${P}.out 2>&1 &

# Initial test
echo -n .; sleep $TIME
echo test-1 >${P}.file
echo -n .; sleep $TIME
echo test-2 >>${P}.file
echo -n .; sleep $TIME

# Test remove
rm ${P}.file || exit 1
echo -n .; sleep $TIME
echo test-3 >${P}.file
echo -n .; sleep $TIME
echo test-4 >>${P}.file
echo -n .; sleep $TIME

# Test move
mv ${P}.file ${P}.moved || exit 1
echo -n .; sleep $TIME
echo test-5 >${P}.file
echo -n .; sleep $TIME
echo test-6 >>${P}.file
echo -n .; sleep $TIME

# Kill logfmon
echo
kill %1

# Cat the output
cat ${P}.out || exit 1

# Clean up
rm -f ${P}.conf ${P}.out ${P}.file ${P}.link ${P}.moved
