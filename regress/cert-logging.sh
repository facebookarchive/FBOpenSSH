tid="cert logging"

CERT_ID="cert_id"
PRINCIPAL=$USER
SERIAL=0

log_grep() {
    if [ "$(grep -c -G "$1" "$TEST_SSHD_LOGFILE")" == "0" ]; then
        return 1;
    else
        return 0;
    fi
}

cat << EOF >> $OBJ/sshd_config
TrustedUserCAKeys $OBJ/ssh-rsa.pub
Protocol 2
PubkeyAuthentication yes
AuthenticationMethods publickey
AuthorizedPrincipalsFile $OBJ/auth_principals
EOF

if [ ! -f $OBJ/trusted_rsa ]; then
    ${SSHKEYGEN} -q -t rsa -C '' -N '' -f $OBJ/trusted_rsa
fi
if [ ! -f $OBJ/untrusted_rsa ]; then
    ${SSHKEYGEN} -q -t rsa -C '' -N '' -f $OBJ/untrusted_rsa
fi

${SSHKEYGEN} -q -s $OBJ/ssh-rsa -I $CERT_ID -n $PRINCIPAL -z $SERIAL $OBJ/trusted_rsa.pub ||
    fatal "Could not create trusted SSH cert"

${SSHKEYGEN} -q -s $OBJ/untrusted_rsa -I $CERT_ID -n $PRINCIPAL -z $SERIAL $OBJ/untrusted_rsa.pub ||
    fatal "Could not create untrusted SSH cert"

CA_FP="$(${SSHKEYGEN} -l -E sha256 -f ssh-rsa | cut -d' ' -f2)"
KEY_FP="$(${SSHKEYGEN} -l -E sha256 -f trusted_rsa | cut -d' ' -f2)"
UNTRUSTED_CA_FP="$(${SSHKEYGEN} -l -E sha256 -f untrusted_rsa | cut -d' ' -f2)"

start_sshd


test_no_principals() {
    echo > $OBJ/auth_principals
    ${SSH} -F $OBJ/ssh_config -i $OBJ/trusted_rsa-cert.pub somehost true ||
        fatal "SSH failed"

    if ! log_grep 'Did not match any principals from auth_principals_\* files'; then
        fail "No 'Did not match any principals' message"
    fi

    if ! log_grep "Rejected cert ID \"$CERT_ID\" with signature $KEY_FP signed by RSA CA $CA_FP via $OBJ/ssh-rsa.pub"; then
        fail "No 'Rejected cert ID' message"
    fi
}


test_with_principals() {
    echo $USER > $OBJ/auth_principals
    ${SSH} -F $OBJ/ssh_config -i $OBJ/trusted_rsa-cert.pub somehost true ||
        fatal "SSH failed"

    if ! log_grep "Matched principal \"$PRINCIPAL\" from $OBJ/auth_principals:1 against \"$PRINCIPAL\" from cert"; then
        fail "No 'Matched principal' message"
    fi
    if ! log_grep "Accepted cert ID \"$CERT_ID\" (serial $SERIAL) with signature $KEY_FP signed by RSA CA $CA_FP via $OBJ/ssh-rsa.pub"; then
        fail "No 'Accepted cert ID' message"
    fi
}


test_untrusted_cert() {
    ${SSH} -F $OBJ/ssh_config -i $OBJ/untrusted_rsa-cert.pub somehost true ||
        fatal "SSH failed"

    if ! log_grep "CA RSA $UNTRUSTED_CA_FP is not listed in $OBJ/ssh-rsa.pub"; then
        fail "No 'CA is not listed' message"
    fi
}


test_no_principals
test_with_principals
test_untrusted_cert
