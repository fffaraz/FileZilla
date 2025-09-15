/*
 * pproxy.c: dummy implementation of platform_new_connection(), to
 * be supplanted on any platform which has its own local proxy
 * method.
 */

#include "putty.h"
#include "network.h"
#include "proxy.h"

Socket *platform_new_connection(SockAddr *addr, const char *hostname,
                                int port, bool privport,
                                bool oobinline, bool nodelay, bool keepalive,
                                Plug *plug, Conf *conf)
{
    return NULL;
}
