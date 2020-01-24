tid="krb5 ccache"

# facebook-only test. Set this to true to run the test. It will only work on facebook devservers.
RUN_TEST=false

if ! $RUN_TEST; then
    warn "Test '$tid' will be skipped. Set RUN_TEST=true to run the test."
    return 0
fi

cat << EOF >> $OBJ/sshd_config
KerberosAuthentication yes
AuthenticationMethods password,keyboard-interactive
EOF

sed -i "s/PasswordAuthentication\tno/PasswordAuthentication\tyes/" $OBJ/ssh_config

start_sshd

# SSH_REGRESS_TMP is deleted on cleanup
read -s -p 'Your Kerberos password is required to run this test as it uses Kerberos authentication: ' PASSWD
echo

SSH_REGRESS_TMP=$(mktemp -d /tmp/openssh-regress-XXXXXX)
echo "echo $PASSWD" > $SSH_REGRESS_TMP/echo_pass.sh
chmod +x $SSH_REGRESS_TMP/echo_pass.sh

setsid env SSH_ASKPASS=$SSH_REGRESS_TMP/echo_pass.sh DISPLAY= ${SSH} -p 4242 localhost true

KRB5CCTEMPLATE=$(cat /etc/krb5.conf | awk '/ssh/,/ccache/{print $3}' | tail -n 1)
KRB5CCNAME=$(echo $KRB5CCTEMPLATE | sed -e "s/%u/$(id -u)/" -e "s/%p/$(cat $PIDFILE)/")

if ! grep "using krb5 ccache $KRB5CCNAME" $TEST_SSHD_LOGFILE > /dev/null; then
    fail "No 'using krb5 ccache' echo"
fi

