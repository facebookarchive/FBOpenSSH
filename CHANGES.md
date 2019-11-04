# Changes

- Add a session identifier to output messages.  This is a unique identifier
based on time in microseconds that applies to a sshd process and its children.

- Output a structured log line when a session is opened, fails to open and is
closed.  The log line contains various data about the session and can be
configured by LogFormatPrefix, LogFormatJson and LogFormatKeys.

- Output a line in the logs whenever a local or remote tunnel is created.

- Increase the maximum number of principals in a certificate to 1024

- Output a line in the logs showing the command run, or shell request and the
user

- Output a line in the logs showing which principal was matched when certificate
authentication was used

- Set an environment variable SSH_CERT_PRINCIPALS in the child process to be the
full principal list of a user's SSH certificate when forced ommand is present
and the user is authenticated by the certificate.

- Read the kerberos ticket cache location from the ssh section of the kerberos
config file.
