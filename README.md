# FBOpenSSH

FBOpenSSH is a fork of OpenSSH with a set of patches developed at Facebook which have been used in production for the past few years.

Facebook operates a large fleet of hosts and to support this the majority of patches fall into two areas:
 * Logging enhancements.  These patches output extra logging to syslog which is consumed downstream.  The structured log
 allow aggregated statistics of all aspects of SSH sessions.
 * Certificate handling.  Facebook [uses SSH certificates](https://engineering.fb.com/security/scalable-and-secure-access-with-ssh/) extensively and some changes to OpenSSH have been made to allow this.

This fork of OpenSSH is currently only built and deployed on Linux.

## Documentation

The official documentation for OpenSSH are the man pages for each tool:

* [ssh(1)](https://man.openbsd.org/ssh.1)
* [sshd(8)](https://man.openbsd.org/sshd.8)
* [ssh-keygen(1)](https://man.openbsd.org/ssh-keygen.1)
* [ssh-agent(1)](https://man.openbsd.org/ssh-agent.1)
* [scp(1)](https://man.openbsd.org/scp.1)
* [sftp(1)](https://man.openbsd.org/sftp.1)
* [ssh-keyscan(8)](https://man.openbsd.org/ssh-keyscan.8)
* [sftp-server(8)](https://man.openbsd.org/sftp-server.8)

## Building Portable OpenSSH

### Dependencies

Portable OpenSSH is built using autoconf and make. It requires a working C compiler, standard library and headers, as well as [zlib](https://www.zlib.net/) and ``libcrypto`` from either [LibreSSL](https://www.libressl.org/) or [OpenSSL](https://www.openssl.org) to build. Certain platforms and build-time options may require additional dependencies.

### Building a release

Releases include a pre-built copy of the ``configure`` script and may be built using:

```
tar zxvf openssh-X.Y.tar.gz
cd openssh
./configure # [options]
make && make tests
```

See the [Build-time Customisation](#build-time-customisation) section below for configure options. If you plan on installing OpenSSH to your system, then you will usually want to specify destination paths.

### Building from git

If building from git, you'll need [autoconf](https://www.gnu.org/software/autoconf/) installed to build the ``configure`` script. The following commands will check out and build portable OpenSSH from git:

```
git clone https://github.com/openssh/openssh-portable # or https://anongit.mindrot.org/openssh.git
cd openssh-portable
autoreconf
./configure
make && make tests
```

### Build-time Customisation

There are many build-time customisation options available. All Autoconf destination path flags (e.g. ``--prefix``) are supported (and are usually required if you want to install OpenSSH).

For a full list of available flags, run ``configure --help`` but a few of the more frequently-used ones are described below. Some of these flags will require additional libraries and/or headers be installed.

Flag | Meaning
--- | ---
``--with-pam`` | Enable [PAM](https://en.wikipedia.org/wiki/Pluggable_authentication_module) support. [OpenPAM](https://www.openpam.org/), [Linux PAM](http://www.linux-pam.org/) and Solaris PAM are supported.
``--with-libedit`` | Enable [libedit](https://www.thrysoee.dk/editline/) support for sftp.
``--with-kerberos5`` | Enable Kerberos/GSSAPI support. Both [Heimdal](https://www.h5l.org/) and [MIT](https://web.mit.edu/kerberos/) Kerberos implementations are supported.
``--with-selinux`` | Enable [SELinux](https://en.wikipedia.org/wiki/Security-Enhanced_Linux) support.

## Code of Conduct
See the [CODE_OF_CONDUCT](CODE_OF_CONDUCT.md) file for details.

## Contributors
See the [CONTRIBUTING](CONTRIBUTING.md) file for how to help out.

## License
FBOpenSSH is BSD licensed.  The original OpenSSH license can be found in the [LICENSE](LICENSE) file.

## Reporting bugs
Bugs can be reported in the Github issue tracker for this repository.
