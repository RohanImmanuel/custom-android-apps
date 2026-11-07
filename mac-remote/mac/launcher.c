// Tiny launcher so macOS Accessibility can be granted to "Mac Remote" alone,
// instead of to the terminal or to every python3 script. It runs remote.py as a
// child; children inherit the app's permission.
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>

extern char **environ;
static pid_t child;
static void forward(int sig) { if (child > 0) kill(child, sig); }

int main(void) {
    char *argv[] = {"/usr/bin/python3", SCRIPT, NULL};
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_addopen(&fa, 1, LOG, O_WRONLY | O_CREAT | O_APPEND, 0600);
    posix_spawn_file_actions_adddup2(&fa, 1, 2);
    signal(SIGTERM, forward);
    signal(SIGINT, forward);
    if (posix_spawn(&child, argv[0], &fa, NULL, argv, environ) != 0) return 1;
    int st = 0;
    while (waitpid(child, &st, 0) < 0) {}
    return WIFEXITED(st) ? WEXITSTATUS(st) : 1;
}
