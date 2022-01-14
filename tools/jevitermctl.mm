#include <cstdio>
#include <cstring>

#include <jeviterm.h>

int main(int argc, const char **argv) {
    if (argc < 2) {
        printf("Usage: jevitermctl <tab 1 command str> <tab 2 command str> ...\n");
        return -1;
    }
    const char *cmds[argc];
    cmds[argc - 1] = nullptr;
    memcpy(cmds, argv + 1, (argc - 1) * sizeof(*cmds));
    return jeviterm_open_tabs(cmds, true, "jevitermctl");
}
