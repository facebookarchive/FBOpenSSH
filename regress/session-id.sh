tid="session id"

start_sshd

${SSH} -F $OBJ/ssh_config somehost true
if [ $? -ne 0 ]; then
	fail "ssh connect with failed"
fi

expected="session=$(hostname)"

# grab the first session ID which will be stable across session
sessionid=$(grep -m1 $expected $TEST_SSHD_LOGFILE | sed -E 's/.*(session=.*)/\1/')

line_count=$(grep -c $expected $TEST_SSHD_LOGFILE)
if [ $line_count == "0" ]; then
	fail "No session ID lines found"
fi

stable_id_count=$(grep -c $sessionid $TEST_SSHD_LOGFILE)
if [ $line_count != $stable_id_count ]; then
	fail 'Mismatching session ids found'
fi
