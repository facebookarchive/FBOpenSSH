tid='structured log'

port="4242"
log_prefix="sshd_auth_msg:"
log_keys="server_ip server_port remote_ip remote_port pid session_id method cert_id cert_serial principal user session_state auth_successful _time command end_time duration auth_info client_version"
do_log_json="yes"
test_config="$OBJ/sshd2_config"
old_config="$OBJ/sshd_config"
PIDFILE=$OBJ/pidfile

cat << EOF > $test_config
	#*:
	StrictModes             no
	Port                    $port
	AddressFamily           inet
	ListenAddress           127.0.0.1
	#ListenAddress          ::1
	PidFile                 $PIDFILE
	AuthorizedKeysFile      $OBJ/authorized_keys_%u
	LogLevel                ERROR
	AcceptEnv               _XXX_TEST_*
	AcceptEnv               _XXX_TEST
	HostKey $OBJ/host.ssh-ed25519
	LogFormatPrefix $log_prefix
	LogFormatJson $do_log_json
	LogFormatKeys $log_keys
EOF


cp $test_config $old_config
start_sshd

${SSH} -F $OBJ/ssh_config somehost true
if [ $? -ne 0 ]; then
	fail "ssh connect with failed"
fi

test_log_counts() {
	cnt=$(grep -c "$log_prefix" "$TEST_SSHD_LOGFILE")
	if [ $cnt -ne 2 ]; then
		fail "expected 2 structured logging lines, got $cnt"
	fi
}

test_json_valid() {
	which python &>/dev/null || echo 'python not found in path, skipping tests'

	loglines=$(cat "$TEST_SSHD_LOGFILE" | grep "$log_prefix")
	first=$(echo "$loglines" | head -n1)
	last=$(echo "$loglines" | tail -n1)

	echo ${first:$(expr length $log_prefix)} | python -m json.tool &>/dev/null \
	    || fail "invalid json structure $first"
	echo ${last:$(expr length $log_prefix)} | python -m json.tool &>/dev/null  \
	    || fail "invalid json structure $last"
}

test_log_counts
test_json_valid
