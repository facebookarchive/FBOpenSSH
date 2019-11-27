tid="session req"

start_sshd

test_user_shell_exec_req() {
  session_shell_req_expected="Exec Request for user $USER with command true"
  cnt=$(grep -c "$session_shell_req_expected" "$TEST_SSHD_LOGFILE")
  if [ $cnt == "0" ]; then
  	fail "No exec request for user log lines found"
  fi
}

test_user_pty() {
  session_pty_req_expected="Allocated pty .* for user $USER session .*"
  line_count=$(grep -c "$session_req_expected" "$TEST_SSHD_LOGFILE")
  if [ $line_count == "0" ]; then
  	fail "No Allocated pty for user session found in log lines"
  fi
}

test_user_shell_req() {
  exit | ${SSH} -F $OBJ/ssh_config somehost
  if [ $? -ne 0 ]; then
  	fail "ssh connect with failed"
  fi
  session_shell_req_expected="Shell Request for user $USER"
  line_count=$(grep -c "$session_shell_req_expected" "$TEST_SSHD_LOGFILE")
  if [ $line_count == "0" ]; then
  	fail "No session request for user log lines found"
  fi
}

${SSH} -F $OBJ/ssh_config somehost true
if [ $? -ne 0 ]; then
	fail "ssh connect with failed"
fi
test_user_shell_exec_req
test_user_pty
test_user_shell_req
