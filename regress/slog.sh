tid='structured log'

log_prefix="sshd_auth_msg:"
log_keys="server_ip server_port remote_ip remote_port pid session_id method cert_id cert_serial principal user session_state auth_successful command end_time duration auth_info client_version"
do_log_json="yes"

AUTH_PRINC_FILE="$OBJ/auth_principals"
CA_FILE="$OBJ/ca-rsa"
IDENTITY_FILE="$OBJ/$USER-rsa"
CERT_ID=$USER

cat << EOF >>	$OBJ/sshd_config
TrustedUserCAKeys $CA_FILE.pub
PubkeyAuthentication yes
AuthenticationMethods publickey
AuthorizedPrincipalsFile $AUTH_PRINC_FILE
LogFormatPrefix $log_prefix
LogFormatJson $do_log_json
LogFormatKeys $log_keys
EOF

sed -i 's/DEBUG3/VERBOSE/g' $OBJ/sshd_config

cleanup() {
	rm -f $CA_FILE{.pub,}
	rm -f $IDENTITY_FILE{-cert.pub,.pub,}
	rm -f $AUTH_PRINC_FILE
	rm -f $TEST_SSHD_LOGFILE
}

make_keys() {
	local keytype=$1

	rm -f $IDENTITY_FILE{.pub,}
	${SSHKEYGEN} -q -t $keytype -C '' -N '' -f $IDENTITY_FILE ||
	    fatal 'Could not create keypair'

	cat $IDENTITY_FILE.pub > authorized_keys_$USER
	${SSHKEYGEN} -lf $IDENTITY_FILE
}

make_cert() {
	local princs=$1
	local certtype=$2
	local serial=$3

	rm -f $CA_FILE
	rm -f "$IDENTITY_FILE-cert.pub"

	${SSHKEYGEN} -q -t $certtype -C '' -N '' -f $CA_FILE ||
	    fatal 'Could not create CA key'

	${SSHKEYGEN} -q -s $CA_FILE -I $CERT_ID -n "$princs" -z $serial "$IDENTITY_FILE.pub" ||
	    fatal "Could not create SSH cert"
}

do_test_log_counts() {
	cnt=$(grep -c "$log_prefix" "$TEST_SSHD_LOGFILE")
	if [ $cnt -ne 2 ]; then
		fail "expected 2 structured logging lines, got $cnt"
	fi
}

test_json_valid() {
	if ! $(which python &>/dev/null) ; then
		 echo 'python not found in path, skipping JSON tests'
		 return 1
	fi

	loglines=$(cat "$TEST_SSHD_LOGFILE" | grep "$log_prefix")
	first=$(echo "$loglines" | head -n1)
	last=$(echo "$loglines" | tail -n1)

	echo ${first:$(expr length $log_prefix)} | python -m json.tool &>/dev/null \
	    || fail "invalid json structure $first"
	echo ${last:$(expr length $log_prefix)} | python -m json.tool &>/dev/null  \
	    || fail "invalid json structure $last"
}

# todo: first/last line
extract_key() {
	local key=$1
	loglines=$(cat "$TEST_SSHD_LOGFILE" | grep "$log_prefix")
	last=$(echo "$loglines" | tail -n1)
	json=${last:$(expr length $log_prefix)}

	val=$(echo $json | python -c "import sys, json; print(json.load(sys.stdin)[\"$key\"])") ||
	    fail "error extracting $key from $json"
	echo "$val"
}

test_basic_logging() {
	${SSH} -F $OBJ/ssh_config -v -i "$IDENTITY_FILE" somehost true ||
		    fatal "SSH failed"

	do_test_log_counts
	test_json_valid || return 1
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

	${SSH} -F $OBJ/ssh_config -v -i "$IDENTITY_FILE" somehost true ||
	    fatal "SSH failed"

	auth_info=$(extract_key 'auth_info')
	digest=$(extract_hash "$keyfp")

	[ -z "$keyfp" ] || echo "$auth_info" | grep -q "$digest" ||
		echo "hash digest not found"
	[ -z "$keytype" ] || echo "$auth_info" | grep -q "$keytype" ||
		echo "keytype not found"
	[ -z "$princ" ] || echo "$auth_info" | grep -q "$princ" ||
		echo "princ not found"
	[ -z "$serial" ] || echo "$auth_info" | grep -q "$serial" ||
		echo "serial not found"
}

test_cert_serial() {
	local serial=$1
	logged_serial=$(extract_key 'cert_serial')
	 [ $serial = $logged_serial ] || fail 'cert serial mismatch'
}

start_sshd

keytype="RSA"
keyfp=$(make_keys $keytype)
test_basic_logging || return
test_auth_info "$keyfp" "$keytype"

rm authorized_keys_$USER # force cert auth

princ="$USER"
echo $princ > $AUTH_PRINC_FILE

serial='42'
make_cert "$princ" "$keytype" "$serial"
test_auth_info "$keyfp" "$keytype" "$princ" "$serial"
test_cert_serial "$serial"
