/*
 * Copyright 2004-present Facebook. All Rights Reserved.
 */

 /* When using slogctxt in any module perform a NULL pointer check */

#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <pwd.h>
#include <time.h>

#include "includes.h"
#include "slog.h"
#include "log.h"
#include "misc.h"
#include "servconf.h"
#include "xmalloc.h"

typedef struct Structuredlogctxt Structuredlogctxt;

struct Structuredlogctxt { /* items we care about logging */
	char		server_ip[SLOG_SHORT_STRING_LEN];		// server_ip
	int		server_port;		// server_port
	char		remote_ip[SLOG_SHORT_STRING_LEN];		// remote_ip
	int		remote_port;		// remote_port
	pid_t		pam_process_pid;		// pam_pid
	char		session_id[SLOG_STRING_LEN];		// session_id
	char		method[SLOG_STRING_LEN];		// method
	char		cert_id[SLOG_STRING_LEN];		// cert_id
	unsigned long long		cert_serial;		// cert_serial
	char		principal[SLOG_STRING_LEN];		// principal
	char		user[SLOG_STRING_LEN];		// user
	char		command[SLOG_LONG_STRING_LEN];		// command
	SLOG_SESSION_STATE		session_state;		// session_state
	SLOG_AUTHENTICATED		auth_successful;		// auth_successful
	time_t		start_time;		// start_time
	time_t		end_time;		// end_time
	int		duration;		// duration
	pid_t		main_pid;		// main_pid
	char		auth_info[SLOG_MEDIUM_STRING_LEN];		// auth_info
	char		client_version[SLOG_STRING_LEN];		// client_version
	struct timeval		auth_start_time;
	struct timeval		last_partial_auth_time;
	struct timeval		auth_end_time;
	double		auth_duration;		// auth_duration
	double		last_partial_auth_duration;		// last_partial_auth_duration
};

Structuredlogctxt *slogctxt;
extern ServerOptions options;

// Define token constants and default syntax format
static const char *server_ip_token         = "server_ip";
static const char *server_port_token       = "server_port";
static const char *remote_ip_token         = "remote_ip";
static const char *remote_port_token       = "remote_port";
static const char *pam_pid_token           = "pam_pid";
static const char *process_pid_token       = "pid";
static const char *session_id_token        = "session_id";
static const char *method_token            = "method";
static const char *cert_id_token           = "cert_id";
static const char *cert_serial_token       = "cert_serial";
static const char *principal_token         = "principal";
static const char *user_token              = "user";
static const char *command_token           = "command";
static const char *session_state_token     = "session_state";
static const char *auth_successful_token   = "auth_successful";
static const char *start_time_token        = "start_time";
static const char *end_time_token          = "end_time";
static const char *duration_token          = "duration";
static const char *main_pid_token          = "main_pid";
static const char *auth_info_token         = "auth_info";
static const char *client_version          = "client_version";
static const char *auth_duration_token     = "auth_duration";
static const char *last_partial_auth_duration_token	=	"last_partial_auth_duration";


/* Example log format sshd_config
 * LogFormatPrefix sshd_auth_msg:
 * LogFormatKeys server_ip server_port remote_ip remote_port pid session_id /
   method cert_id cert_serial principal user session_state auth_successful /
   start_time command # NO LINE BREAKS
 * LogFormatJson yes # no makes this output an json array vs json object
 */

// Set a arbitrary large size so we can feed a potentially
// large json object to the logger
#define SLOG_BUF_SIZE 8192
#define SLOG_TRUNCATED_MESSAGE_JSON ", \"incomplete\": \"true\"}"
#define SLOG_TRUNCATED_MESSAGE_ARRAY ", \"incomplete\"]"
#define SLOG_TRUNCATED_SIZE 25
/* size of format for JSON for quotes_colon_space around key and comma_space
   after value or closure_null */
#define SLOG_JSON_FORMAT_SIZE 6
#define SLOG_BUF_CALC_SIZE  SLOG_BUF_SIZE - SLOG_TRUNCATED_SIZE

/* private declarations */
static void slog_log(void);
static void slog_cleanup(void);
static void slog_generate_auth_payload(char *);
static void slog_escape_value(char *, char *, size_t);
static void slog_get_safe_from_token(char *, const char *);
static const char* slog_get_state_text(void);

/* public functions */

void
slog_init(void)
{
	/* initialize only if we have log_format_keys */
	if (options.num_log_format_keys != 0) {
		slogctxt = xcalloc(1, sizeof(Structuredlogctxt));
		if (slogctxt != NULL)
			slog_cleanup();
	}
}

void
slog_pam_session_opened(void)
{
	if (slogctxt != NULL) {
		slogctxt->session_state = SLOG_SESSION_OPEN;
		slogctxt->pam_process_pid = getpid();
	}
}

void
slog_set_auth_start(void)
{
	if (slogctxt != NULL) {
		gettimeofday(&slogctxt->auth_start_time, NULL);
	}
}

void
slog_set_last_partial_auth_time(void)
{
	if (slogctxt != NULL) {
		if (gettimeofday(&slogctxt->last_partial_auth_time, NULL) == 0) {
			struct timeval res;
			timersub(&slogctxt->last_partial_auth_time, &slogctxt->auth_start_time, &res);
			slogctxt->last_partial_auth_duration = res.tv_sec + (res.tv_usec / 1000000.0);
		}
	}
}

void
slog_set_auth_end(void)
{
	if (slogctxt != NULL) {
		if (gettimeofday(&slogctxt->auth_end_time, NULL) == 0) {
			struct timeval res;
			timersub(&slogctxt->auth_end_time, &slogctxt->auth_start_time, &res);
			slogctxt->auth_duration = res.tv_sec + (res.tv_usec / 1000000.0);
		}
	}
}

void
slog_set_auth_data(int authenticated, const char *method, const char *user)
{
	if (slogctxt != NULL) {
		slogctxt->auth_successful =
		    authenticated ? SLOG_AUTHORIZED : SLOG_UNAUTHORIZED;
		strlcpy(slogctxt->method, method, SLOG_SHORT_STRING_LEN);
		strlcpy(slogctxt->user, user, SLOG_STRING_LEN);
	}
}

void
slog_set_cert_id(const char *id)
{
	if (slogctxt != NULL)
		strlcpy(slogctxt->cert_id, id, SLOG_STRING_LEN);
}


void
slog_set_cert_serial(unsigned long long serial)
{
	if (slogctxt != NULL)
		slogctxt->cert_serial = serial;
}

void
slog_set_connection(const char *remote_ip, int remote_port,
    const char *server_ip, int server_port, const char *session)
{
	if (slogctxt != NULL) {
		strlcpy(slogctxt->remote_ip, remote_ip, SLOG_SHORT_STRING_LEN);
		slogctxt->remote_port = remote_port;
		strlcpy(slogctxt->server_ip, server_ip, SLOG_SHORT_STRING_LEN);
		slogctxt->server_port = server_port;
		strlcpy(slogctxt->session_id, session, SLOG_STRING_LEN);
		slogctxt->start_time = time(NULL);
		slogctxt->main_pid = getpid();
	}
}

void
slog_set_client_version(const char *version)
{
	if (slogctxt != NULL) {
		if (strlen(version) < SLOG_STRING_LEN)
			strlcpy(slogctxt->client_version, version, SLOG_STRING_LEN);
		else {
			// version can be up to 256 bytes, truncate to 95 and add ' ...'
			// which will fit in SLOG_STRING_LEN
			snprintf(slogctxt->client_version, SLOG_STRING_LEN, "%.95s ...", version);
		}
	}
}

void
slog_set_command(const char *command)
{
	if (slogctxt != NULL) {
		if (strlen(command) < SLOG_LONG_STRING_LEN)
			strlcpy(slogctxt->command, command, SLOG_LONG_STRING_LEN);
		else {
			// If command is longer than allowed we truncate it to
			// 1995 (SLOG_LONG_STRING_LEN - 5) characters and add ' ...\0' to
			// the end of the command.
			snprintf(slogctxt->command, SLOG_LONG_STRING_LEN, "%.1995s ...", command);
		}
	}
}

void
slog_set_principal(const char *principal)
{
	if (slogctxt != NULL)
		strlcpy(slogctxt->principal, principal, SLOG_STRING_LEN);
}

void
slog_set_user(const char *user)
{
	if (slogctxt != NULL)
		strlcpy(slogctxt->user, user, SLOG_STRING_LEN);
}

void
slog_set_auth_info(const char *auth_info)
{
	if (slogctxt != NULL)
		strlcpy(slogctxt->auth_info, auth_info, SLOG_MEDIUM_STRING_LEN);
}

void
slog_exit_handler(void)
{
	/* to prevent duplicate logging we only log based on the pid set */
	if (slogctxt != NULL) {
		if (slogctxt->server_ip[0] == 0)
			return; // not initialized
		if (slogctxt->main_pid != getpid())
			return; // not main process
		if (slogctxt->session_state == SLOG_SESSION_INIT)
			slog_log();
		else {
			slogctxt->session_state = SLOG_SESSION_CLOSED;
			slogctxt->end_time = time(NULL);
			slogctxt->duration = slogctxt->end_time - slogctxt->start_time;
			slog_log();
			slog_cleanup();
		}
  }
}

void
slog_log_session(void)
{
	if (slogctxt != NULL) {
		slogctxt->session_state = SLOG_SESSION_OPEN;
		slog_log();
	}
}

/* private function scope begin */

static void
slog_log(void)
{
	char *buffer = xmalloc(SLOG_BUF_SIZE);

	if (buffer == NULL)
		return;

	memset(buffer, 0, SLOG_BUF_SIZE);

	if (options.num_log_format_keys > 0
	    && slogctxt != NULL
	    && slogctxt->server_ip[0] != 0
	    && slogctxt->user[0] != 0) {
		slog_generate_auth_payload(buffer);
		do_log_slog_payload(buffer);
	}

	free(buffer);
}

static void
slog_cleanup(void)
{
	// Reset the log context values
	if (slogctxt != NULL) {
		memset(slogctxt, 0, sizeof(Structuredlogctxt));
		slogctxt->session_state = SLOG_SESSION_INIT;
		slogctxt->auth_successful = SLOG_UNAUTHORIZED;
	}
}

/* We use debug3 since the debug is very noisy */
static void
slog_generate_auth_payload(char *buf)
{
	if (buf == NULL)
		return;

	// Create large buffer so don't risk overflow
	char *safe = xmalloc(SLOG_BUF_SIZE);
	memset(safe, 0, SLOG_BUF_SIZE);

	if (safe == NULL)
		return;

	int i;
	size_t remaining;
	int json = options.log_format_json;
	int keys = options.num_log_format_keys;
	int truncated = 0;
	char *tmpbuf = buf;
	char *key;

	debug3("JSON format is %d with %d tokens.", json, keys);

	if (options.log_format_prefix != NULL
	    && strlen(options.log_format_prefix) < SLOG_BUF_CALC_SIZE-1) {
		tmpbuf += snprintf(tmpbuf, SLOG_BUF_CALC_SIZE,
	    "%s ", options.log_format_prefix);
	}
	*tmpbuf++ = (json) ? '{' : '[';
	debug3("current buffer after prefix: %s", buf);

	// Loop through the keys filling out the output string
	for (i = 0; i < keys; i++) {
		safe[0] = 0;  // clear safe string
		key = options.log_format_keys[i];
		remaining = SLOG_BUF_CALC_SIZE - (tmpbuf - buf);

		if (key == NULL)
			continue;  // Shouldn't happen but if null go to next key

		slog_get_safe_from_token(safe, key);
		debug3("token: %s, value: %s", key, safe);

		if (json) {
			if (*safe == '\0')
				continue; // No value since we are using key pairs skip
			if (remaining <= SLOG_JSON_FORMAT_SIZE + strlen(key) + strlen(safe)) {
				debug("Log would exceed buffer size %u, %zu, %zu at key: %s",
				    (unsigned int)remaining, strlen(key), strlen(safe), key);
				truncated = 1;
				break;
			}
			tmpbuf += snprintf(tmpbuf, remaining, "%s\"%s\": %s",
			    i > 0 ? ", " : "", key, safe);
		} else {
			if (*safe == '\0')
				strlcpy(safe, "\"\"", SLOG_SHORT_STRING_LEN);
			if (remaining < SLOG_JSON_FORMAT_SIZE + strlen(safe)) {
				debug("Log would exceed remaining buffer size %d, %zu, at key: %s",
				    (unsigned int)remaining, strlen(safe), key);
				truncated = 1;
				break;
			}
			tmpbuf += snprintf(tmpbuf, remaining, "%s%s", i > 0 ? ", " : "", safe);
		}
		debug3("current buffer after token: %s", buf);
		debug3("end of loop key: %s, %d out of %d keys", key, i + 1, keys);
	}

	// Close the log string. If truncated set truncated message and close string
	if (truncated == 1)
		strlcpy(tmpbuf, json ? SLOG_TRUNCATED_MESSAGE_JSON :
		    SLOG_TRUNCATED_MESSAGE_ARRAY, SLOG_TRUNCATED_SIZE);
	else {
		*tmpbuf++ = (json) ? '}' : ']';
	}

	free(safe);
}

// buffer size is input string * 2 +1
static void
slog_escape_value(char *output, char *input, size_t buffer_size)
{
	int i;
	buffer_size -= 2;
	if (input != NULL) {
		int input_size = strlen(input);
		char *temp = output;
		*temp++ = '"';
		buffer_size--;
		for (i = 0; i < input_size && buffer_size > 0; i++) {
			switch(input[i]) {
			// characters escaped are the same as folly::json::escapeString
			case 27: // <escape> ascii control character
				if (buffer_size > 6) {
					*temp++ = '\\';
					*temp++ = 'u';
					*temp++ = '0';
					*temp++ = '0';
					*temp++ = '1';
					*temp++ = 'b';
					buffer_size -= 6;
				}
			case '\b':
				if (buffer_size > 1) {
					*temp++ = '\\';
					*temp++ = 'b';
					buffer_size -= 2;
				}
				break;
			case '\f':
				if (buffer_size > 1) {
					*temp++ = '\\';
					*temp++ = 'f';
					buffer_size -= 2;
				}
				break;
			case '\n':
				if (buffer_size > 1) {
					*temp++ = '\\';
					*temp++ = 'n';
					buffer_size -= 2;
					}
				break;
			case '\r':
				if (buffer_size > 1) {
					*temp++ = '\\';
					*temp++ = 'r';
					buffer_size -= 2;
				}
				break;
			case '\t':
				if (buffer_size > 1) {
					*temp++ = '\\';
					*temp++ = 't';
					buffer_size -= 2;
				}
				break;
			case '\"':
			case '\\':
				if (buffer_size > 1) {
					*temp++ = '\\';
					buffer_size--;
			}
			default:  // Non-escape char
				*temp++ = input[i];
				buffer_size--;
			}
		}
		*temp++ = '"';
		*temp++ = '\0';
	}
}

static void
slog_get_safe_from_token(char *output, const char *token)
{
	if (output == NULL || token == NULL || slogctxt == NULL)
		return;

	if (strcmp(token, server_ip_token) == 0) {
		if (slogctxt->server_ip[0] != 0) {
			snprintf(output, SLOG_SHORT_STRING_LEN, "\"%s\"",
			    slogctxt->server_ip);
		}
		return;
	}

	if (strcmp(token, server_port_token) == 0) {
		if (slogctxt->server_port > 0) {
			snprintf(output, SLOG_SHORT_STRING_LEN, "\"%d\"",
			slogctxt->server_port);
		}
		return;
	}

	if (strcmp(token, remote_ip_token) == 0) {
		if (slogctxt->remote_ip[0] != 0) {
			snprintf(output, SLOG_SHORT_STRING_LEN, "\"%s\"",
			    slogctxt->remote_ip);
		}
		return;
	}

	if (strcmp(token, remote_port_token) == 0) {
		if (slogctxt->remote_port > 0) {
			snprintf(output, SLOG_SHORT_STRING_LEN, "\"%d\"",
			    slogctxt->remote_port);
		}
		return;
	}

	if (strcmp(token, pam_pid_token) == 0) {
		if (slogctxt->pam_process_pid > 0) {
			snprintf(output, SLOG_SHORT_STRING_LEN, "\"%ld\"",
			    (long)slogctxt->pam_process_pid);
		}
		return;
	}

	if (strcmp(token, process_pid_token) == 0) {
		snprintf(output, SLOG_SHORT_STRING_LEN, "\"%ld\"", (long)getpid());
		return;
	}

	if (strcmp(token, session_id_token) == 0) {
		if (slogctxt->session_id[0] != 0) {
				snprintf(output, SLOG_STRING_LEN, "\"%s\"",
				    slogctxt->session_id);
		}
		return;
	}

	if (strcmp(token, method_token) == 0) {
		if (slogctxt->method[0] != 0) {
				snprintf(output, SLOG_STRING_LEN, "\"%s\"",
				    slogctxt->method);
		}
		return;
	}

	// Arbitrary input
	if (strcmp(token, cert_id_token) == 0) {
		if (slogctxt->cert_id[0] != 0 &&
		    strcmp(slogctxt->method, "publickey") == 0) {
				slog_escape_value(output, slogctxt->cert_id,
				    SLOG_STRING_LEN * 2 + 1);
		}
		return;
	}

	if (strcmp(token, cert_serial_token) == 0) {
		if (slogctxt->cert_serial > 0 &&
		    strcmp(slogctxt->method, "publickey") == 0) {
			snprintf(output, SLOG_SHORT_STRING_LEN, "\"%llu\"",
			    slogctxt->cert_serial);
		}
		return;
	}

	// Arbitrary input
	if (strcmp(token, principal_token) == 0) {
		if (slogctxt->principal[0] != 0) {
			slog_escape_value(output, slogctxt->principal,
			    SLOG_STRING_LEN * 2 + 1);
		}
	return;
	}

	// Arbitrary input
	if (strcmp(token, user_token) == 0) {
		if (slogctxt->user[0] != 0) {
			slog_escape_value(output, slogctxt->user,
		    SLOG_STRING_LEN * 2 + 1);
		}
		return;
	}

	// Arbitrary input
	if (strcmp(token, auth_info_token) == 0) {
		if (slogctxt->auth_info[0] != 0) {
			slog_escape_value(output, slogctxt->auth_info,
			    SLOG_MEDIUM_STRING_LEN * 2 + 1);
		}
		return;
	}

	// Arbitrary input
	if (strcmp(token, command_token) == 0) {
		if (slogctxt->command[0] != 0) {
			slog_escape_value(output, slogctxt->command,
			    SLOG_LONG_STRING_LEN * 2 + 1);
		}
		return;
	}

	if (strcmp(token, auth_successful_token) == 0) {
		snprintf(output, SLOG_SHORT_STRING_LEN, "\"%s\"",
		    slogctxt->auth_successful == SLOG_AUTHORIZED ? "true" : "false");
		return;
	}

	if (strcmp(token, session_state_token) == 0) {
		snprintf(output, SLOG_SHORT_STRING_LEN, "\"%s\"",
		    slog_get_state_text());
		return;
	}

	if (strcmp(token, start_time_token) == 0) {
		snprintf(output, SLOG_SHORT_STRING_LEN, "\"%d\"",
		    (int)slogctxt->start_time);
		return;
	}

	if (strcmp(token, end_time_token) == 0 && slogctxt->end_time > 0) {
		snprintf(output, SLOG_SHORT_STRING_LEN, "\"%d\"",
		    (int)slogctxt->end_time);
		return;
	}

	if (strcmp(token, duration_token) == 0 && slogctxt->end_time > 0) {
		snprintf(output, SLOG_SHORT_STRING_LEN, "\"%d\"", slogctxt->duration);
		return;
	}

	if (strcmp(token, auth_duration_token) == 0 && slogctxt->auth_end_time.tv_sec > 0) {
		snprintf(output, SLOG_SHORT_STRING_LEN, "\"%f\"", slogctxt->auth_duration);
		return;
	}

	if (strcmp(token, last_partial_auth_duration_token) == 0 && timerisset(&slogctxt->last_partial_auth_time)) {
		snprintf(output, SLOG_SHORT_STRING_LEN, "\"%f\"", slogctxt->last_partial_auth_duration);
		return;
	}

	if (strcmp(token, main_pid_token) == 0) {
		if (slogctxt->main_pid > 0) {
			snprintf(output, SLOG_SHORT_STRING_LEN, "\"%ld\"",
			    (long)slogctxt->main_pid);
		}
		return;
	}

	// Arbitrary input
	if (strncmp(token, client_version, strlen(client_version)) == 0) {
		if (slogctxt->client_version[0] != 0) {
			slog_escape_value(output, slogctxt->client_version,
			    SLOG_STRING_LEN + 2);
		}
		return;
	}
}

static const char *
slog_get_state_text(void)
{
	if (slogctxt == NULL)
		return "";

	switch (slogctxt->session_state) {
		case SLOG_SESSION_INIT:
			return "Session failed";
		case SLOG_SESSION_OPEN:
			return "Session opened";
		case SLOG_SESSION_CLOSED:
			return "Session closed";
		default:
			return "Unknown session state";  // Should never happen
	}
}
