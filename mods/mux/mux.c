#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE 1
#define _GNU_SOURCE 1

/* ndx-mod.h must come first so it sets __NDX_CALLER_PATH_DEFINED__ before
 * ndx.h is pulled in transitively by ndc.h */
#include <ttypt/ndx-mod.h>
#include <ttypt/ndc.h>
#include <ttypt/qmap.h>
#include <ttypt/qsys.h>

#include <arpa/telnet.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#if defined(__APPLE__) || defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__NetBSD__)
#include <util.h>
#else
#include <pty.h>
#endif
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#ifndef NDC_PREFIX
#define NDC_PREFIX "/usr/local"
#endif

#ifndef NDC_HTDOCS
#define NDC_HTDOCS NDC_PREFIX "/share/ndc/htdocs"
#endif

/* OpenBSD may not define ECHOCTL */
#ifndef ECHOCTL
#define ECHOCTL 0
#endif

/* ------------------------------------------------------------------ */
/* Per-connection PTY state stored in the module qmap                  */
/* ------------------------------------------------------------------ */

struct mux_state {
  int            pty;  /* PTY master fd; -1 = none */
  int            pid;  /* child PID; -1 = none */
  struct winsize wsz;
  struct termios tty;
};

/* fd (uint32) → struct mux_state */
static uint32_t mux_map;
/* pty_fd (uint32) → client_fd (uint32) reverse lookup */
static uint32_t mux_pty_map;

static uint32_t mux_state_type;  /* qmap type id for struct mux_state */

static struct mux_state *
mux_get(socket_t fd)
{
  return (struct mux_state *)qmap_get(mux_map, &(uint32_t){(uint32_t)fd});
}

static struct mux_state *
mux_put(socket_t fd, struct mux_state *s)
{
  qmap_put(mux_map, &(uint32_t){(uint32_t)fd}, s);
  return (struct mux_state *)qmap_get(mux_map, &(uint32_t){(uint32_t)fd});
}

static void
mux_del(socket_t fd)
{
  qmap_del(mux_map, &(uint32_t){(uint32_t)fd});
}

/* Helpers */

/* server-user password entry */
static struct passwd mux_pw;

static void
ndc_pw_free(struct passwd *target)
{
  free(target->pw_name);
  free(target->pw_shell);
  free(target->pw_dir);
}

static void
ndc_pw_copy(struct passwd *target, struct passwd *origin)
{
  *target = *origin;
  target->pw_name  = strdup(origin->pw_name);
  target->pw_shell = strdup(origin->pw_shell);
  target->pw_dir   = strdup(origin->pw_dir);
  target->pw_passwd = NULL;
}

static void
ndc_tty_update(socket_t fd)
{
  struct mux_state *s = mux_get(fd);
  if (!s || s->pty < 0)
    return;

  struct termios last = s->tty;

  if ((last.c_lflag & ECHO) != (s->tty.c_lflag & ECHO))
    TELNET_CMD(fd, IAC, s->tty.c_lflag & ECHO ? WILL : WONT, TELOPT_ECHO);

  if ((last.c_lflag & ICANON) != (s->tty.c_lflag & ICANON))
    TELNET_CMD(fd, IAC, s->tty.c_lflag & ICANON ? WONT : WILL, TELOPT_SGA);

  tcgetattr(s->pty, &s->tty);
  tcflush(s->pty, TCIFLUSH);
}

static struct passwd *
drop_priviledges(socket_t fd)
{
  int euid = geteuid();

  struct passwd local_pw;
  struct passwd *pw;

  if (ndc_get_pw(fd, &local_pw) == 0) {
    /* authenticated — use the connection user; pw_name etc. point into
       local_pw which is on the stack, but we only use it before execve */
    pw = &local_pw;
  } else {
    pw = &mux_pw;
  }

  if (!ndc_config.chroot) {
    WARN("NOT_CHROOTED - running with %s\n", pw->pw_name);
    return pw;
  }

  if (euid != 0) {
    WARN("NOT_ROOT - skipping privilege drop for %s\n", pw->pw_name);
    return pw;
  }

  CBUG(!pw, "getpwnam\n");
  CBUG(setgroups(0, NULL), "setgroups\n");
  CBUG(initgroups(pw->pw_name, pw->pw_gid), "initgroups\n");
  CBUG(setgid(pw->pw_gid), "setgid\n");
  CBUG(setuid(pw->pw_uid), "setuid\n");

  return pw;
}

/* PTY fork */

static inline int
command_pty(socket_t cfd, struct winsize *ws, char * const args[])
{
  struct mux_state *s = mux_get(cfd);
  CBUG(!s, "command_pty: no mux state for fd %d\n", cfd);

  ndc_fd_watch(s->pty);

  /* Mark the pty fd's reverse entry as "this is a pty master" (pid=-2) */
  struct mux_state pty_sentinel = { .pty = -2, .pid = -2 };
  qmap_put(mux_pty_map, &(uint32_t){(uint32_t)s->pty},
      &(uint32_t){(uint32_t)cfd});
  (void)pty_sentinel; /* used above for documentation */

  pid_t p = fork();
  if (p == 0) { /* child */
    ndc_fork_child_reset();

    CBUG(setsid() == -1, "setsid\n");

    CBUG(!(ndc_flags(cfd) & DF_AUTHENTICATED), "NOT AUTHENTICATED\n");

    int slave_fd = open(ptsname(s->pty), O_RDWR);
    CBUG(slave_fd == -1, "open %d\n", errno);

    drop_priviledges(cfd);
    struct passwd local_pw;
    if (ndc_get_pw(cfd, &local_pw) != 0) {
      local_pw = mux_pw;
    }

    (void) fcntl(slave_fd, F_GETFL, 0);

    close(s->pty);

    CBUG(ioctl(slave_fd, TIOCSCTTY, NULL) == -1, "ioctl TIOCSCTTY\n");
    CBUG(ioctl(slave_fd, TIOCSWINSZ, ws)  == -1, "ioctl TIOCSWINSZ\n");
    CBUG(fcntl(slave_fd, F_SETFD, FD_CLOEXEC) == -1,
        "fcntl srv_fd F_SETFL FD_CLOEXEC\n");

    CBUG(dup2(slave_fd, STDIN_FILENO)  == -1, "dup2 STDIN\n");
    CBUG(dup2(slave_fd, STDOUT_FILENO) == -1, "dup2 STDOUT\n");
    CBUG(dup2(slave_fd, STDERR_FILENO) == -1, "dup2 STDERR\n");

    char *alt_args[] = { local_pw.pw_shell, NULL };
    char * const *real_args = args[0] ? args : alt_args;
    char home[BUFSIZ], user[BUFSIZ], shell[BUFSIZ];
    snprintf(home,  sizeof(home),  "HOME=%s",  local_pw.pw_dir);
    snprintf(user,  sizeof(user),  "USER=%s",  local_pw.pw_name);
    snprintf(shell, sizeof(shell), "SHELL=%s", local_pw.pw_shell);

    char * const env[] = {
      "PATH=/bin:/usr/bin:/usr/local/bin",
      "LD_LIBRARY_PATH=/lib:/usr/lib:/usr/local/lib",
      home, user, shell,
      NULL,
    };

    execve(real_args[0], real_args, env);
    CBUG(1, "execve\n");
  }

  return p;
}

NDX_DEF(int, ndc_mux_exec,
    socket_t, fd,
    char **, argv)
{
  struct mux_state *s = mux_get(fd);
  if (!s)
    return -1;
  s->pid = command_pty(fd, &s->wsz, (char * const *)argv);
  ndc_fd_watch(s->pty);
  return 0;
}

NDX_DEF(int, ndc_mux_shell, socket_t, fd)
{
  char *argv[] = { NULL, NULL };
  return call_ndc_mux_exec(fd, argv);
}

static void
do_sh(socket_t fd,
    int argc UNUSED,
    char *argv[] UNUSED)
{
  call_ndc_mux_shell(fd);
}

/* NDX hook implementations */

NDX_DEF(int, telnet_connected,
    socket_t, fd)
{
  struct mux_state s;
  memset(&s, 0, sizeof(s));
  s.pty = -1;
  s.pid = -1;

  /* Send initial TELNET negotiations */
  TELNET_CMD(fd, IAC, WILL, TELOPT_ECHO);
  TELNET_CMD(fd, IAC, WONT, TELOPT_SGA);

  s.tty.c_lflag = ICANON | ECHO | ECHOK | ECHOCTL;
  s.tty.c_iflag = IGNCR;
  s.tty.c_iflag &= ~ICRNL;
  s.tty.c_iflag &= ~INLCR;
  s.tty.c_oflag |= OPOST | ONLCR;
  s.tty.c_oflag &= ~OCRNL;

  CBUG(fcntl(fd, F_SETFL, O_NONBLOCK) == -1,
      "telnet_connected fcntl F_SETFL O_NONBLOCK\n");

  s.pty = posix_openpt(O_RDWR | O_NOCTTY);
  CBUG(s.pty == -1,  "telnet_connected posix_openpt\n");
  CBUG(grantpt(s.pty),  "telnet_connected grantpt\n");
  CBUG(unlockpt(s.pty), "telnet_connected unlockpt\n");

  struct mux_state *sp = mux_put(fd, &s);

  /* reverse pty→client map */
  qmap_put(mux_pty_map, &(uint32_t){(uint32_t)sp->pty},
      &(uint32_t){(uint32_t)fd});

  tcsetattr(sp->pty, TCSANOW, &sp->tty);
  ndc_tty_update(fd);

  if (sp->wsz.ws_col || sp->wsz.ws_row)
    ioctl(sp->pty, TIOCSWINSZ, &sp->wsz);

  return 0;
}

NDX_DEF(int, telnet_parse,
    socket_t, fd,
    unsigned char *, input,
    int, nread)
{
  struct mux_state *s = mux_get(fd);
  if (!s)
    return 0;

  int i = 0;

  for (; i < nread && input[i] != IAC; i++);

  if (i == nread)
    i = 0;

  while (i < nread && input[i + 0] == IAC) {
    if (input[i + 1] == SB && input[i + 2] == TELOPT_NAWS) {
      unsigned char colsHighByte = input[i + 3];
      unsigned char colsLowByte  = input[i + 4];
      unsigned char rowsHighByte = input[i + 5];
      unsigned char rowsLowByte  = input[i + 6];

      memset(&s->wsz, 0, sizeof(s->wsz));
      s->wsz.ws_col = (colsHighByte << 8) | colsLowByte;
      s->wsz.ws_row = (rowsHighByte << 8) | rowsLowByte;

      if (s->pty > 0)
        ioctl(s->pty, TIOCSWINSZ, &s->wsz);

      i += 9;
    } else if (input[i + 1] == DO && input[i + 2] == TELOPT_SGA) {
      i += 3;
    } else if (input[i + 1] == DO) {
      i += 3;
    } else if (input[i + 1] == DONT) {
      i += 3;
    } else if (input[i + 1] == WILL) {
      i += 3;
    } else {
      i++;
    }
  }

  if (s->pid > 0 && i < nread) {
    write(s->pty, input + i, nread - i);
    return -1; /* signal: consumed by PTY, skip cmd_parse */
  }

  return i;
}

NDX_DEF(int, on_fd_tick, socket_t, fd)
{
  /* fd here is an externally-watched fd — look up the client fd */
  const uint32_t *cfd_p = qmap_get(mux_pty_map, &(uint32_t){(uint32_t)fd});

  if (!cfd_p)
    return -1;

  socket_t cfd = (socket_t)*cfd_p;

  struct mux_state *s = mux_get(cfd);
  if (!s)
    return -1;

  static char buf[BUFSIZ * 4];
  int ret, status;

  memset(buf, 0, sizeof(buf));
  errno = 0;
  ret = read(fd, buf, sizeof(buf));

  switch (ret) {
    case 0:
      if (s->pid > 0 && waitpid(s->pid, &status, WNOHANG) == 0)
        return 0;
      break;
    case -1:
      if (errno == EAGAIN || errno == EIO)
        return 0;
      return -1;
    default:
      buf[ret] = '\0';
      ndc_write(cfd, buf, ret);
      ndc_tty_update(cfd);
      return ret;
  }

  if (s->pid > 0)
    kill(s->pid, SIGKILL);

  s->pid = -1;
  return ret;
}

NDX_DEF(int, telnet_cleanup, socket_t, fd)
{
  struct mux_state *s = mux_get(fd);
  if (!s)
    return 0;

  if (s->pty > 0) {
    if (s->pid > 0)
      kill(-s->pid, SIGKILL);
    s->pid = -1;
    ndc_fd_unwatch(s->pty);
    qmap_del(mux_pty_map, &(uint32_t){(uint32_t)s->pty});
    close(s->pty);
    s->pty = -1;
  }

  mux_del(fd);
  return 0;
}

/* Asset serving */

static int
handle_ndc_js(socket_t fd, char *body)
{
  (void)body;
  ndc_sendfile(fd, NDC_HTDOCS "/ndc.js");
  return 0;
}

static int
handle_ndc_css(socket_t fd, char *body)
{
  (void)body;
  ndc_sendfile(fd, NDC_HTDOCS "/ndc.css");
  return 0;
}

static int
handle_ndc_tty_js(socket_t fd, char *body)
{
  (void)body;
  ndc_sendfile(fd, NDC_HTDOCS "/ndc-tty.js");
  return 0;
}

/* Module entry points */

void
ndx_install(void)
{
  /* Allocate qmap types and maps */
  mux_state_type = qmap_reg(sizeof(struct mux_state));
  mux_map     = qmap_open(NULL, NULL, QM_U32, mux_state_type, 0xFF, 0);
  mux_pty_map = qmap_open(NULL, NULL, QM_U32, QM_U32,         0xFF, 0);

  /* Cache server-user pw entry */
  char euname[BUFSIZ] = "root";
  strncpy(euname, getpwuid(geteuid())->pw_name, sizeof(euname) - 1);
  ndc_pw_copy(&mux_pw, getpwnam(euname));

  /* Register the shell command */
  ndc_register("sh", do_sh, CF_NOTRIM);

  /* Serve browser terminal assets */
  ndc_register_handler("GET:/ndc.js",     handle_ndc_js);
  ndc_register_handler("GET:/ndc.css",    handle_ndc_css);
  ndc_register_handler("GET:/ndc-tty.js", handle_ndc_tty_js);
}
