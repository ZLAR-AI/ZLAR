// Native macOS peer-credential boundary for Demo 1.
// launchd owns the AF_UNIX listener. This broker derives the caller EUID with
// getpeereid(3), admits only Vincent's actual client domain UID 501, and passes one bounded request to
// one protected Node destination child through private pipes.

#include <arpa/inet.h>
#include <errno.h>
#include <launch.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define SERVICE_UID 450
#define SERVICE_GID 450
#define CLIENT_UID 501
#define MAX_FRAME (1024U * 1024U)
#define SOCKET_NAME "Demo1DestinationSocket"
#define NODE_PATH "/usr/local/libexec/zlar-demo1/node"
#define SERVICE_PATH "/usr/local/libexec/zlar-demo1/demos/zlar-destination-gate/demo1-installed-service.mjs"

extern char **environ;

static int read_exact(int fd, unsigned char *buffer, size_t length) {
  size_t offset = 0;
  while (offset < length) {
    ssize_t count = read(fd, buffer + offset, length - offset);
    if (count == 0) return -1;
    if (count < 0) {
      if (errno == EINTR) continue;
      return -1;
    }
    offset += (size_t)count;
  }
  return 0;
}

static int write_exact(int fd, const unsigned char *buffer, size_t length) {
  size_t offset = 0;
  while (offset < length) {
    ssize_t count = write(fd, buffer + offset, length - offset);
    if (count < 0) {
      if (errno == EINTR) continue;
      return -1;
    }
    offset += (size_t)count;
  }
  return 0;
}

static int send_frame(int fd, const unsigned char *body, size_t length) {
  if (length == 0 || length > MAX_FRAME) return -1;
  uint32_t network_length = htonl((uint32_t)length);
  if (write_exact(fd, (const unsigned char *)&network_length, sizeof(network_length)) != 0) return -1;
  return write_exact(fd, body, length);
}

static void send_refusal(int fd, const char *reason) {
  char body[256];
  int length = snprintf(body, sizeof(body),
    "{\"reason\":\"%s\",\"status\":\"REFUSED\",\"v\":1}", reason);
  if (length > 0 && (size_t)length < sizeof(body)) {
    (void)send_frame(fd, (const unsigned char *)body, (size_t)length);
  }
}

static int run_destination(const unsigned char *request, size_t request_length,
                           unsigned char **response_out, size_t *response_length_out) {
  int input_pipe[2] = {-1, -1};
  int output_pipe[2] = {-1, -1};
  posix_spawn_file_actions_t actions;
  pid_t child = -1;
  int status = 0;
  unsigned char *response = NULL;
  size_t response_length = 0;
  int result = -1;

  if (pipe(input_pipe) != 0 || pipe(output_pipe) != 0) goto cleanup;
  if (posix_spawn_file_actions_init(&actions) != 0) goto cleanup;
  if (posix_spawn_file_actions_adddup2(&actions, input_pipe[0], STDIN_FILENO) != 0 ||
      posix_spawn_file_actions_adddup2(&actions, output_pipe[1], STDOUT_FILENO) != 0 ||
      posix_spawn_file_actions_addclose(&actions, input_pipe[1]) != 0 ||
      posix_spawn_file_actions_addclose(&actions, output_pipe[0]) != 0) {
    posix_spawn_file_actions_destroy(&actions);
    goto cleanup;
  }

  char *const argv[] = {
    (char *)NODE_PATH,
    (char *)"--disable-proto=throw",
    (char *)SERVICE_PATH,
    (char *)"--peer-uid",
    (char *)"501",
    NULL,
  };
  char *const child_environment[] = {
    (char *)"PATH=/usr/bin:/bin",
    (char *)"LANG=C",
    (char *)"LC_ALL=C",
    (char *)"TMPDIR=/var/db/zlar-demo1",
    NULL,
  };
  int spawn_result = posix_spawn(&child, NODE_PATH, &actions, NULL, argv, child_environment);
  posix_spawn_file_actions_destroy(&actions);
  if (spawn_result != 0) goto cleanup;

  close(input_pipe[0]); input_pipe[0] = -1;
  close(output_pipe[1]); output_pipe[1] = -1;
  if (write_exact(input_pipe[1], request, request_length) != 0) goto cleanup;
  close(input_pipe[1]); input_pipe[1] = -1;

  response = malloc(MAX_FRAME + 1U);
  if (response == NULL) goto cleanup;
  for (;;) {
    ssize_t count = read(output_pipe[0], response + response_length, MAX_FRAME + 1U - response_length);
    if (count == 0) break;
    if (count < 0) {
      if (errno == EINTR) continue;
      goto cleanup;
    }
    response_length += (size_t)count;
    if (response_length > MAX_FRAME) goto cleanup;
  }
  close(output_pipe[0]); output_pipe[0] = -1;
  while (waitpid(child, &status, 0) < 0) {
    if (errno != EINTR) goto cleanup;
  }
  child = -1;
  if (response_length == 0 || (!WIFEXITED(status)) ||
      (WEXITSTATUS(status) != 0 && WEXITSTATUS(status) != 42)) goto cleanup;
  *response_out = response;
  *response_length_out = response_length;
  response = NULL;
  result = 0;

cleanup:
  if (input_pipe[0] >= 0) close(input_pipe[0]);
  if (input_pipe[1] >= 0) close(input_pipe[1]);
  if (output_pipe[0] >= 0) close(output_pipe[0]);
  if (output_pipe[1] >= 0) close(output_pipe[1]);
  if (child > 0) {
    kill(child, SIGKILL);
    while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
  }
  free(response);
  return result;
}

static void serve_client(int client_fd) {
  uid_t peer_uid = (uid_t)-1;
  gid_t peer_gid = (gid_t)-1;
  if (getpeereid(client_fd, &peer_uid, &peer_gid) != 0) {
    send_refusal(client_fd, "peer_credentials_unavailable");
    return;
  }
  if (peer_uid != CLIENT_UID) {
    send_refusal(client_fd, "peer_uid_refused");
    return;
  }

  uint32_t network_length = 0;
  if (read_exact(client_fd, (unsigned char *)&network_length, sizeof(network_length)) != 0) {
    send_refusal(client_fd, "frame_header_invalid");
    return;
  }
  uint32_t request_length = ntohl(network_length);
  if (request_length == 0 || request_length > MAX_FRAME) {
    send_refusal(client_fd, "frame_length_refused");
    return;
  }
  unsigned char *request = malloc(request_length);
  if (request == NULL) {
    send_refusal(client_fd, "broker_memory_failure");
    return;
  }
  if (read_exact(client_fd, request, request_length) != 0) {
    free(request);
    send_refusal(client_fd, "frame_body_invalid");
    return;
  }
  unsigned char trailing = 0;
  ssize_t peeked = recv(client_fd, &trailing, 1, MSG_PEEK | MSG_DONTWAIT);
  if (peeked > 0) {
    free(request);
    send_refusal(client_fd, "multiple_requests_refused");
    return;
  }

  unsigned char *response = NULL;
  size_t response_length = 0;
  if (run_destination(request, request_length, &response, &response_length) != 0) {
    free(request);
    send_refusal(client_fd, "destination_child_failure");
    return;
  }
  free(request);
  (void)send_frame(client_fd, response, response_length);
  free(response);
}

int main(void) {
  if (geteuid() != SERVICE_UID || getegid() != SERVICE_GID) return 78;
  signal(SIGPIPE, SIG_IGN);

  int *sockets = NULL;
  size_t socket_count = 0;
  if (launch_activate_socket(SOCKET_NAME, &sockets, &socket_count) != 0 ||
      sockets == NULL || socket_count != 1) {
    free(sockets);
    return 78;
  }
  int listener = sockets[0];
  free(sockets);

  for (;;) {
    int client = accept(listener, NULL, NULL);
    if (client < 0) {
      if (errno == EINTR) continue;
      return 70;
    }
    serve_client(client);
    close(client);
  }
}
