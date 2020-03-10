tid='structured log'

LOG_PREFIX="sshd_auth_msg:"
LOG_KEYS="server_ip server_port remote_ip remote_port pid session_id method cert_id cert_serial principal user session_state auth_successful command start_time end_time duration auth_info client_version"
DO_LOG_JSON="yes"

KEYTYPE="RSA"
AUTH_PRINC_FILE="$OBJ/auth_principals"
CA_FILE="$OBJ/ca-rsa"
IDENTITY_FILE="$OBJ/$USER-rsa"
CERT_ID="$USER"
CERT_SERIAL="42"
CERT_PRINC="$USER"

sed -i 's/DEBUG3/VERBOSE/g' $OBJ/sshd_config

cat << EOF >>	$OBJ/sshd_config
TrustedUserCAKeys $CA_FILE.pub
PubkeyAuthentication yes
AuthenticationMethods publickey
AuthorizedPrincipalsFile $AUTH_PRINC_FILE
LogFormatPrefix $LOG_PREFIX
LogFormatJson $DO_LOG_JSON
LogFormatKeys $LOG_KEYS
EOF

if [ -z "$SUDO" ]; then
	verbose "PAM sessions won't be tested unless the test is run with SUDO"
else
	echo "UsePAM yes" >> $OBJ/sshd_config
fi

cleanup() {
	stop_sshd
	rm -f $CA_FILE{.pub,}
	rm -f $IDENTITY_FILE{-cert.pub,.pub,}
	rm -f $AUTH_PRINC_FILE
	rm -f $TEST_SSHD_LOGFILE
}

make_keypair() {
	local keytype=$1
	local filename=$2

	rm -f $filename{.pub,}

	${SSHKEYGEN} -q -t $keytype -C '' -N '' -f $filename ||
		fatal 'Could not create keypair'

	(
		printf 'localhost-with-alias,127.0.0.1,::1 '
		cat $filename.pub
	) >> $OBJ/known_hosts
	echo "IdentityFile $filename" >> $OBJ/ssh_config
	cat $filename.pub > $OBJ/authorized_keys_$USER
	${SSHKEYGEN} -lf $filename
}

make_cert() {
	local cert_file=$1
	local cert_id=$2
	local serial=$3
	local princs=$4

	rm -f $cert_file-cert.pub

	if [ ! -f $CA_FILE ]; then
		${SSHKEYGEN} -q -t $KEYTYPE -C '' -N '' -f $CA_FILE ||
			fatal 'Could not create CA keypair'
	fi
	
	${SSHKEYGEN} -q -s "$CA_FILE" -I "$cert_id" -n "$princs" -z "$serial" "$cert_file.pub" ||
		fatal 'Could not create SSH cert'
}

json_grep() {
	local key=$1
	local logline=$2
	[ -z "$logline" ] && read -r logline
	if echo "$logline" | grep -Eq "^$LOG_PREFIX"; then
		local json="${logline:$(expr length "$LOG_PREFIX")}"
	else
		local json="$logline"
	fi

	if val=$(echo "$json" | python -c "import sys, json; print(json.load(sys.stdin)['$key'])" 2>/dev/null); then
		echo "$val"
	else
		return 1
	fi
}

extract_key() {
	json_grep "$1" "$(grep "$LOG_PREFIX" "$TEST_SSHD_LOGFILE" | tail -n1)" ||
		return 1
}

test_basic_logging() {
	local cnt=$(grep -c "$LOG_PREFIX" "$TEST_SSHD_LOGFILE")
	if [ $cnt -ne 2 ]; then
		fail "expected 2 structured logging lines, got $cnt"
	fi

	if ! which python &>/dev/null; then
		echo 'python not found in path, skipping JSON tests'
		return 1
	fi

	local loglines=$(grep "$LOG_PREFIX" "$TEST_SSHD_LOGFILE")
	local first=$(echo "$loglines" | head -n1)
	local last=$(echo "$loglines" | tail -n1)

	echo ${first:$(expr length $LOG_PREFIX)} | python -m json.tool &>/dev/null ||
		fail "invalid json structure $first"
	echo ${last:$(expr length $LOG_PREFIX)} | python -m json.tool &>/dev/null ||
		fail "invalid json structure $last"
}

extract_hash() {
	local source=$1
	echo $source | sed "s/.*\(SHA256:[[:print:]]\{43\}\).*$/\1/"
}

test_auth_info() {
	local keyfp=$1
	local keytype=$2
	local princ=$3
	local serial=$4

	auth_info=$(extract_key 'auth_info') ||
		fail "no auth info"
	digest=$(extract_hash "$keyfp")

	[ -z "$keyfp" ] || echo "$auth_info" | grep -q "$digest" ||
		fail "hash digest not found"
	[ -z "$keytype" ] || echo "$auth_info" | grep -q "$keytype" ||
		fail "keytype not found"
	[ -z "$princ" ] || echo "$auth_info" | grep -q "$princ" ||
		fail "princ not found"
	[ -z "$serial" ] || echo "$auth_info" | grep -q "$serial" ||
		fail "serial not found"
}

test_cert() {
	local serial=$1
	local princ=$2
	local cert_id=$3

	logged_serial=$(extract_key 'cert_serial') ||
		fail 'no cert_serial'
	[ "$serial" = "$logged_serial" ] ||
		fail 'cert serial mismatch'

	logged_princ=$(extract_key 'principal') ||
		fail 'no principal'
	[ "$princ" = "$logged_princ" ] ||
		fail 'principal mismatch'

	logged_cert_id=$(extract_key 'cert_id') ||
		fail 'no cert_id'
	[ "$cert_id" = "$logged_cert_id" ] ||
		fail 'cert_id mismatch'
}

test_client_version() {
	client_version="$(extract_key 'client_version')" ||
		fail 'no client version'
	echo "$client_version" | grep -Eq '^OpenSSH' ||
		fail 'invalid client version'
}

test_failed_session() {
	success=$(extract_key 'auth_successful') ||
		fail "no auth_successful"
	[ "$success" == "false" ] ||
		fail 'auth_successful mismatch'

	state=$(extract_key 'session_state') ||
		fail "no session_state"
	[ "$state" = "Session failed" ] ||
		fail "session_state mismatch"
}

test_session() {
	local last_lines=$(grep "$LOG_PREFIX" "$TEST_SSHD_LOGFILE" | tail -n2)
	local start="$(echo "$last_lines" | head -n1)"
	local end="$(echo "$last_lines" | tail -n1)"

	for key in server_ip server_port remote_ip remote_port session_id method \
			cert_id cert_serial principal user auth_successful auth_info \
			client_version; do
		start_key="$(echo "$start" | json_grep $key)" || fail "no start $key"
		end_key="$(echo "$end" | json_grep $key)" || fail "no end $key"
		[ "$start_key" = "$end_key" ] || fail "$key mismatch: $start_key != $end_key"
	done

	start_state=$(echo "$start" | json_grep 'session_state') ||
		fail "no start session state"
	[ "$start_state" = "Session opened" ] || fail "invalid start session state"

	[ -z "$SUDO" ] && return  # The following only works when the test runs with SUDO

	end_state=$(echo "$end" | json_grep 'session_state') ||
		fail "no end session state"
	[ "$end_state" = "Session closed" ] || fail "invalid end session state"

	start_time=$(echo "$end" | json_grep 'start_time') || fail "no start_time"
	date -d @$start_time &>/dev/null || fail "invalid start_time"
	end_time=$(echo "$end" | json_grep 'end_time') || fail "no end_time"
	date -d @$end_time &>/dev/null || fail "invalid end_time"
	duration=$(echo "$end" | json_grep 'duration') || fail "no duration"
	[ "$duration" -eq "$(($end_time - $start_time))" ] 2>/dev/null ||
		fail "duration mismatch"
}

keyfp=$(make_keypair "$KEYTYPE" "$IDENTITY_FILE")
make_cert "$IDENTITY_FILE" "$CERT_ID" "$CERT_SERIAL" "$CERT_PRINC"

start_sshd

${SSH} -F $OBJ/ssh_config -i "$IDENTITY_FILE" somehost true ||
	fatal "SSH failed"

test_basic_logging
test_auth_info "$keyfp" "$keytype"

echo > $AUTH_PRINC_FILE

${SSH} -F $OBJ/ssh_config -i "$IDENTITY_FILE-cert.pub" somehost true &&
	fatal "SSH succeeded unexpectedly"

test_failed_session

echo $CERT_PRINC > $AUTH_PRINC_FILE

${SSH} -F $OBJ/ssh_config -i "$IDENTITY_FILE-cert.pub" somehost true ||
	fatal "SSH failed"

test_auth_info "$keyfp" "$KEYTYPE" "$CERT_PRINC" "$CERT_SERIAL"
test_cert "$CERT_SERIAL" "$CERT_PRINC" "$CERT_ID"
test_client_version
test_session
