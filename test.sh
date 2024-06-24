#!/bin/bash
set -euo pipefail
# set -x

HOST_A_CMD="ssh scionclient1"
HOST_B_CMD="ssh scionclient2"

A_API="192.168.10.92:8000"
A_SRV="17-ffaa:1:fe2,192.168.10.121:8000"
A_IFACE="ens5f0"
B_SRV="17-ffaa:1:113c,192.168.10.141:8000"
B_IFACE="ens5f0"

testfile="testfile"
testfile2="testfile2"
testdir="testdir"
destfile="destfile"
destfile2="destfile2"
destdir="destdir"

tmux kill-session -t hercules-test || true
tmux new-session -d -s hercules-test

$HOST_A_CMD dd if=/dev/urandom bs=1K count=50 of="$testfile"
$HOST_A_CMD dd if=/dev/urandom bs=1K count=50 of="$testfile2"
$HOST_A_CMD sudo "mkdir -p ${testdir}; for i in {1..10}; do echo \$i > $testdir/file\$i; done;"
$HOST_B_CMD sudo rm -rf "$destfile"
$HOST_B_CMD sudo rm -rf "$destfile2"
$HOST_B_CMD sudo rm -rf "$destdir"
testfile_sum=$($HOST_A_CMD md5sum $testfile | cut -d ' ' -f1)
testfile2_sum=$($HOST_A_CMD md5sum $testfile2 | cut -d ' ' -f1)

$HOST_A_CMD "echo 'ListenAddress = \"$A_SRV\"' > test_a.toml"
$HOST_A_CMD "echo 'Interfaces = [\"$A_IFACE\"]' >> test_a.toml"
# $HOST_A_CMD "echo 'ConfigureQueues = false' >> test_a.toml"

$HOST_B_CMD "echo 'ListenAddress = \"$B_SRV\"' > test_b.toml"
$HOST_B_CMD "echo 'Interfaces = [\"$B_IFACE\"]' >> test_b.toml"
# $HOST_B_CMD "echo 'ConfigureQueues = false' >> test_b.toml"

# # Start the monitor
tmux new-window -n mon_a -t hercules-test: "$HOST_A_CMD"
tmux send-keys -t hercules-test:mon_a sudo\ ./hercules-monitor\ -c\ test_a.toml ENTER
sleep 0.5

# # Start the server
tmux new-window -n srv_a -t hercules-test: "$HOST_A_CMD"
tmux send-keys -t hercules-test:srv_a sudo\ ./hercules-server\ -c\ test_a.toml ENTER

# # Start the monitor
tmux new-window -n mon_b -t hercules-test: "$HOST_B_CMD"
tmux send-keys -t hercules-test:mon_b sudo\ ./hercules-monitor\ -c\ test_b.toml ENTER
sleep 0.5

# # Start the server
tmux new-window -n srv_b -t hercules-test: "$HOST_B_CMD"
tmux send-keys -t hercules-test:srv_b sudo\ ./hercules-server\ -c\ test_b.toml ENTER

quit () {
    set +e
    $HOST_A_CMD sudo pkill hercules-server
    $HOST_B_CMD sudo pkill hercules-server
    exit 1
}

# # Transfer a single file
echo "Submitting single file"
id=$(curl -s "$A_API/submit?file=$testfile&dest=$B_SRV&destfile=$destfile" | cut -d ' ' -f 2)
echo "Job has id $id"
sleep 1

while true; do
echo -n "."
response=$(curl -s "$A_API/status?id=$id")
status=$(echo "$response" | cut -d ' ' -f 2)
err=$(echo "$response" | cut -d ' ' -f 4)
if [[ "$status" == "3" ]]
then
   break
fi
sleep 1
done

echo ""
if [[ "$err" == 1 ]]
then
echo "File transfer done"
else
    echo "File transfer error: $err"
    quit
fi
destfile_sum=$($HOST_B_CMD md5sum $destfile | cut -d ' ' -f1)
if [[ $destfile_sum != $testfile_sum ]]
then
    echo "Checksum mismatch!"
    quit
fi

# Transfer a directory
echo "Submitting directory"
id=$(curl -s "$A_API/submit?file=$testdir&dest=$B_SRV&destfile=$destdir" | cut -d ' ' -f 2)
echo "Job has id $id"
sleep 1

while true; do
echo -n "."
response=$(curl -s "$A_API/status?id=$id")
status=$(echo "$response" | cut -d ' ' -f 2)
err=$(echo "$response" | cut -d ' ' -f 4)
if [[ "$status" == "3" ]]
then
   break
fi
sleep 1
done

echo ""
if [[ "$err" == 1 ]]
then
echo "Directory transfer complete"
else
    echo "Directory transfer error"
    quit
fi
for i in {1..10};
do
    if [[ $($HOST_B_CMD "sudo cat $destdir/file$i") != $i ]]
    then
        echo "File content incorrect"
        quit
    fi
done

# Transfer multiple files concurrently
echo "Submitting 2 files"
id=$(curl -s "$A_API/submit?file=$testfile&dest=$B_SRV&destfile=$destfile" | cut -d ' ' -f 2)
echo "Job has id $id"
id2=$(curl -s "$A_API/submit?file=$testfile2&dest=$B_SRV&destfile=$destfile2" | cut -d ' ' -f 2)
echo "Job 2 has id $id2"
sleep 1

while true; do
echo -n "."
response=$(curl -s "$A_API/status?id=$id")
response2=$(curl -s "$A_API/status?id=$id2")
status=$(echo "$response" | cut -d ' ' -f 2)
status2=$(echo "$response2" | cut -d ' ' -f 2)
err=$(echo "$response" | cut -d ' ' -f 4)
err2=$(echo "$response2" | cut -d ' ' -f 4)
if [[ "$status" == "3" && "$status2" == 3 ]]
then
   break
fi
sleep 1
done

echo ""
if [[ "$err" == 1 && "$err2" == 1 ]]
then
echo "Multiple file transfer complete"
else
    echo "Multiple file transfer error"
    quit
fi

destfile_sum=$($HOST_B_CMD md5sum $destfile | cut -d ' ' -f1)
destfile2_sum=$($HOST_B_CMD md5sum $destfile2 | cut -d ' ' -f1)
if [[ $destfile_sum != $testfile_sum || $destfile2_sum != $testfile2_sum ]]
then
    echo "Checksum mismatch!"
    quit
fi

quit
