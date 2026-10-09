/* Offline test entry point. The nfqws2 sources and C Lua API are unchanged.
 * Only Lua is initialized: no NFQUEUE, raw sockets, privilege changes or
 * firewall setup. test_alt11.lua captures the sender before invoking desync.
 */
#include "params.h"
#include "lua.h"
#include "pools.h"
#include "nfqws.h"
#include <stdio.h>

struct params_s params;
volatile sig_atomic_t bQuit = 0;

int main(int argc, char **argv)
{
    init_params(&params);
    for (int i = 1; i < argc; i++)
        if (!strlist_add_tail(&params.lua_init_scripts, argv[i])) return 2;
    int status = lua_init() ? 0 : 1;
    cleanup_params(&params);
    return status;
}
