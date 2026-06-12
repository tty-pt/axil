#include "../include/ttypt/axil.h"

#include <stdio.h>

/* Stub implementations for weak symbols (needed for Windows/MinGW/macOS linking) */
#if defined(_WIN32) || defined(__APPLE__)
void axil_update(unsigned long long dt) { (void)dt; }
void axil_vim(socket_t fd, int argc, char *argv[]) { (void)fd; (void)argc; (void)argv; }
int axil_accept(socket_t fd) { (void)fd; return 0; }
int axil_connect(socket_t fd) { (void)fd; return 0; }
void axil_disconnect(socket_t fd) { (void)fd; }
void axil_command(socket_t fd, int argc, char *argv[]) { (void)fd; (void)argc; (void)argv; }
void axil_flush(socket_t fd, int argc, char *argv[]) { (void)fd; (void)argc; (void)argv; }
char *axil_auth_check(socket_t fd) { (void)fd; return NULL; }
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
	printf("libaxil public api\n");

	expect_sym_data("axil_tick", &axil_tick);
	expect_sym_data("axil_config", &axil_config);
	expect_sym_fn("axil_register", (void (*)(void)) axil_register);
	expect_sym_fn("axil_main", (void (*)(void)) axil_main);
	expect_sym_fn("axil_register_handler", (void (*)(void)) axil_register_handler);
	expect_sym_fn("axil_write", (void (*)(void)) axil_write);
	expect_sym_fn("axil_dwritef", (void (*)(void)) axil_dwritef);
	expect_sym_fn("axil_writef", (void (*)(void)) axil_writef);
	expect_sym_fn("axil_wall", (void (*)(void)) axil_wall);
	expect_sym_fn("do_GET", (void (*)(void)) do_GET);
	expect_sym_fn("do_POST", (void (*)(void)) do_POST);
	expect_sym_fn("axil_flags", (void (*)(void)) axil_flags);
	expect_sym_fn("axil_close", (void (*)(void)) axil_close);
	expect_sym_fn("axil_set_flags", (void (*)(void)) axil_set_flags);
	expect_sym_fn("axil_auth", (void (*)(void)) axil_auth);
	expect_sym_fn("axil_cert_add", (void (*)(void)) axil_cert_add);
	expect_sym_fn("axil_certs_add", (void (*)(void)) axil_certs_add);
	expect_sym_fn("axil_mmap", (void (*)(void)) axil_mmap);
	expect_sym_fn("axil_mmap_iter", (void (*)(void)) axil_mmap_iter);
	expect_sym_fn("axil_env_clear", (void (*)(void)) axil_env_clear);
	expect_sym_fn("axil_env", (void (*)(void)) axil_env);
	expect_sym_fn("axil_env_get", (void (*)(void)) axil_env_get);
	expect_sym_fn("axil_env_put", (void (*)(void)) axil_env_put);
	expect_sym_fn("axil_exec", (void (*)(void)) axil_exec);
	expect_sym_data("axil_execbuf", axil_execbuf);

#if defined(_WIN32) || defined(__APPLE__)
	expect_weak("axil_update", 1);
	expect_weak("axil_vim", 1);
	expect_weak("axil_accept", 1);
	expect_weak("axil_connect", 1);
	expect_weak("axil_disconnect", 1);
	expect_weak("axil_command", 1);
	expect_weak("axil_flush", 1);
	expect_weak("axil_auth_check", 1);
#else
	expect_weak("axil_update", &axil_update != NULL);
	expect_weak("axil_vim", &axil_vim != NULL);
	expect_weak("axil_accept", &axil_accept != NULL);
	expect_weak("axil_connect", &axil_connect != NULL);
	expect_weak("axil_disconnect", &axil_disconnect != NULL);
	expect_weak("axil_command", &axil_command != NULL);
	expect_weak("axil_flush", &axil_flush != NULL);
	expect_weak("axil_auth_check", &axil_auth_check != NULL);
#endif

	printf("errors=%u\n", errors);
	return (int)errors;
}
