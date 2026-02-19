#include "../include/ttypt/ndc.h"

#include <stdio.h>

/* Stub implementations for weak symbols (needed for Windows/MinGW linking) */
#ifdef _WIN32
void ndc_update(unsigned long long dt) { (void)dt; }
void ndc_vim(socket_t fd, int argc, char *argv[]) { (void)fd; (void)argc; (void)argv; }
int ndc_accept(socket_t fd) { (void)fd; return 0; }
int ndc_connect(socket_t fd) { (void)fd; return 0; }
void ndc_disconnect(socket_t fd) { (void)fd; }
void ndc_command(socket_t fd, int argc, char *argv[]) { (void)fd; (void)argc; (void)argv; }
void ndc_flush(socket_t fd, int argc, char *argv[]) { (void)fd; (void)argc; (void)argv; }
char *ndc_auth_check(socket_t fd) { (void)fd; return NULL; }
#endif

static unsigned errors = 0;

static void
expect_sym_data(const char *name, const void *ptr)
{
	(void)ptr;
	printf("%s ok\n", name);
}

static void
expect_sym_fn(const char *name, void (*fn)(void))
{
	(void)fn;
	printf("%s ok\n", name);
}

static void
expect_weak(const char *name, int present)
{
	if (present) {
		printf("%s set\n", name);
		return;
	}
	printf("%s unset\n", name);
}

int
main(void)
{
	printf("libndc public api\n");

	expect_sym_data("ndc_tick", &ndc_tick);
	expect_sym_data("ndc_config", &ndc_config);
	expect_sym_fn("ndc_register", (void (*)(void)) ndc_register);
	expect_sym_fn("ndc_main", (void (*)(void)) ndc_main);
	expect_sym_fn("ndc_register_handler", (void (*)(void)) ndc_register_handler);
	expect_sym_fn("ndc_write", (void (*)(void)) ndc_write);
	expect_sym_fn("ndc_dwritef", (void (*)(void)) ndc_dwritef);
	expect_sym_fn("ndc_writef", (void (*)(void)) ndc_writef);
	expect_sym_fn("ndc_wall", (void (*)(void)) ndc_wall);
	expect_sym_fn("do_GET", (void (*)(void)) do_GET);
	expect_sym_fn("do_POST", (void (*)(void)) do_POST);
	expect_sym_fn("do_sh", (void (*)(void)) do_sh);
	expect_sym_fn("ndc_pty", (void (*)(void)) ndc_pty);
	expect_sym_fn("ndc_flags", (void (*)(void)) ndc_flags);
	expect_sym_fn("ndc_close", (void (*)(void)) ndc_close);
	expect_sym_fn("ndc_set_flags", (void (*)(void)) ndc_set_flags);
	expect_sym_fn("ndc_auth", (void (*)(void)) ndc_auth);
	expect_sym_fn("ndc_cert_add", (void (*)(void)) ndc_cert_add);
	expect_sym_fn("ndc_certs_add", (void (*)(void)) ndc_certs_add);
	expect_sym_fn("ndc_mmap", (void (*)(void)) ndc_mmap);
	expect_sym_fn("ndc_mmap_iter", (void (*)(void)) ndc_mmap_iter);
	expect_sym_fn("ndc_env_clear", (void (*)(void)) ndc_env_clear);
	expect_sym_fn("ndc_env", (void (*)(void)) ndc_env);
	expect_sym_fn("ndc_env_get", (void (*)(void)) ndc_env_get);
	expect_sym_fn("ndc_env_put", (void (*)(void)) ndc_env_put);
	expect_sym_fn("ndc_exec", (void (*)(void)) ndc_exec);
	expect_sym_data("ndc_execbuf", ndc_execbuf);

	expect_weak("ndc_update", &ndc_update != NULL);
	expect_weak("ndc_vim", &ndc_vim != NULL);
	expect_weak("ndc_accept", &ndc_accept != NULL);
	expect_weak("ndc_connect", &ndc_connect != NULL);
	expect_weak("ndc_disconnect", &ndc_disconnect != NULL);
	expect_weak("ndc_command", &ndc_command != NULL);
	expect_weak("ndc_flush", &ndc_flush != NULL);
	expect_weak("ndc_auth_check", &ndc_auth_check != NULL);

	printf("errors=%u\n", errors);
	return (int)errors;
}
