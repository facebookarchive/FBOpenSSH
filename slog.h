/*
 * Copyright 2004-present Facebook. All Rights Reserved.
 */
#ifndef USE_SLOG
#define USE_SLOG

#define SLOG_STRING_LEN        100
#define SLOG_MEDIUM_STRING_LEN 1000
#define SLOG_SHORT_STRING_LEN  50
#define SLOG_LONG_STRING_LEN   2000

typedef enum {
	SLOG_SESSION_INIT,
	SLOG_SESSION_OPEN,
	SLOG_SESSION_CLOSED,
} SLOG_SESSION_STATE;

typedef enum {
	SLOG_UNAUTHORIZED = 0,
	SLOG_AUTHORIZED = 1
} SLOG_AUTHENTICATED;

void	slog_init(void);

// setters
void	slog_pam_session_opened(void);
void	slog_set_auth_data(int , const char *, const char *);
void	slog_set_cert_id(const char *);
void	slog_set_cert_serial(unsigned long long );
void	slog_set_connection(const char *, int, const char *, int, const char *);
void	slog_set_command(const char *);
void	slog_set_principal(const char *);
void	slog_set_user(const char *);
void	slog_set_auth_info(const char *);
void	slog_set_client_version(const char *);
void	slog_set_auth_start(void);
void	slog_set_auth_end(void);
void	slog_set_last_partial_auth_time(void);

// loggers
void	slog_exit_handler(void);
void	slog_log_session(void);

#endif
