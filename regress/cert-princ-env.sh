tid="cert principal env"

# change to ecdsa
CERT_ID="$USER"
AUTH_PRINC_FILE="$OBJ/auth_principals"
CA_FILE="$OBJ/ca-rsa"
IDENTITY_FILE="$OBJ/$USER-rsa"
SSH_MAX_PUBKEY_BYTES=16384

cat << EOF >> $OBJ/sshd_config
TrustedUserCAKeys $CA_FILE.pub
Protocol 2
PubkeyAuthentication yes
AuthenticationMethods publickey
AuthorizedPrincipalsFile $AUTH_PRINC_FILE
ForceCommand=/bin/env
EOF

cleanup() {
	rm -f $CA_FILE{.pub,}
	rm -f $IDENTITY_FILE{-cert.pub,.pub,}
	rm -f $AUTH_PRINC_FILE
}

make_keys_and_certs() {
	rm -f $CA_FILE{.pub,}
	rm -f $IDENTITY_FILE{-cert.pub,.pub,}

  local princs=$1

	${SSHKEYGEN} -q -t rsa -C '' -N '' -f $CA_FILE ||
	    fatal 'Could not create CA key'

	${SSHKEYGEN} -q -t rsa -C '' -N '' -f $IDENTITY_FILE ||
	    fatal 'Could not create keypair'

	${SSHKEYGEN} -q -s $CA_FILE -I $CERT_ID -n "$princs" -z "42" "$IDENTITY_FILE.pub" ||
	    fatal "Could not create SSH cert"
}

test_with_expected_principals() {
	local princs=$1

	out=$(${SSH} -E thlog -F $OBJ/ssh_config -i "$IDENTITY_FILE" somehost false) ||
	    fatal "SSH failed"

	echo "$out" | grep -q "SSH_CERT_PRINCIPALS=$princs$" ||
	    fatal "SSH_CERT_PRINCIPALS has incorrect value"
}

test_with_no_expected_principals() {
	local princs=$1

	out=$(${SSH} -E thlog -F $OBJ/ssh_config -i "$IDENTITY_FILE" somehost false) ||
	    fatal "SSH failed"

	echo "$out" | grep -vq "SSH_CERT_PRINCIPALS" ||
	    fatal "SSH_CERT_PRINCIPALS env should not be set"

	echo "$out" | grep -vq "SSH_CERT_PRINCIPALS=$princs" ||
	    fatal "SSH_CERT_PRINCIPALS has incorrect value"
}


echo 'a' > $AUTH_PRINC_FILE
start_sshd

principals="a,b,c,d"
make_keys_and_certs "$principals"
test_with_expected_principals "$principals"

big_princ=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16381 | head -n 1)
make_keys_and_certs "a,$big_princ"
test_with_expected_principals "a,$big_princ"

# No room for two principals
big_princ=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16382 | head -n 1)
make_keys_and_certs "a,$big_princ"
test_with_expected_principals "a"

make_keys_and_certs "$big_princ,a"
test_with_expected_principals "$big_princ"

big_princ=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16384 | head -n 1)
make_keys_and_certs "a,$big_princ"
test_with_expected_principals "a"

# principal too big for buffer
big_princ=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w $SSH_MAX_PUBKEY_BYTES | head -n 1)
make_keys_and_certs "$big_princ"
test_with_no_expected_principals "$big_princ"

# no matching principals in certificate and auth princ file
principals="b,c,d"
make_keys_and_certs "$principals"
test_with_no_expected_principals "$principals"

stop_sshd

cat << EOF >> $OBJ/sshd_config
TrustedUserCAKeys $CA_FILE.pub
Protocol 2
PubkeyAuthentication yes
AuthenticationMethods publickey
AuthorizedPrincipalsFile $AUTH_PRINC_FILE
EOF

start_sshd

# no force command, no princpals
principals="a,b,c,d"
make_keys_and_certs "$principals"
test_with_no_expected_principals "$principals"

stop_sshd

cat << EOF >> $OBJ/sshd_config
Protocol 2
PubkeyAuthentication yes
AuthenticationMethods publickey
AuthorizedPrincipalsFile $AUTH_PRINC_FILE
EOF

start_sshd

# No TrustedUserCAKeys causes pubkey auth, no principals
principals="a,b,c,d"
make_keys_and_certs "$principals"
test_with_no_expected_principals "$principals"
