/*=========================================================================*\
* Internet domain functions
* LuaSocket toolkit
*
* RCS ID: $Id: inet.c,v 1.28 2005/10/07 04:40:59 diego Exp $
\*=========================================================================*/
#include <stdio.h>
#include <string.h>

#include "lua.h"
#include "lauxlib.h"

#include "inet.h"

/*=========================================================================*\
* Internal function prototypes.
\*=========================================================================*/
static int inet_global_toip(lua_State *L);
static int inet_global_tohostname(lua_State *L);
static void inet_pushresolved(lua_State *L, struct hostent *hp);
static int inet_global_gethostname(lua_State *L);

/* DNS functions */
static luaL_reg func[] = {
    { "toip", inet_global_toip },
    { "tohostname", inet_global_tohostname },
    { "gethostname", inet_global_gethostname},
    { NULL, NULL}
};

/*=========================================================================*\
* Exported functions
\*=========================================================================*/
/*-------------------------------------------------------------------------*\
* Initializes module
\*-------------------------------------------------------------------------*/
int inet_open(lua_State *L)
{
    lua_pushstring(L, "dns");
    lua_newtable(L);
    luaL_openlib(L, NULL, func, 0);
    lua_settable(L, -3);
    return 0;
}

/*=========================================================================*\
* Global Lua functions
\*=========================================================================*/
/*-------------------------------------------------------------------------*\
* Returns all information provided by the resolver given a host name
* or ip address
\*-------------------------------------------------------------------------*/
static int inet_gethost(const char *address, struct hostent **hp) {
    struct in_addr addr;
    if (inet_aton(address, &addr))
        return socket_gethostbyaddr((char *) &addr, sizeof(addr), hp);
    else 
        return socket_gethostbyname(address, hp);
}

/*-------------------------------------------------------------------------*\
* Returns all information provided by the resolver given a host name
* or ip address
\*-------------------------------------------------------------------------*/
static int inet_global_tohostname(lua_State *L) {
    const char *address = luaL_checkstring(L, 1);
    struct hostent *hp = NULL; 
    int err = inet_gethost(address, &hp);
    if (err != IO_DONE) {
        lua_pushnil(L);
        lua_pushstring(L, socket_hoststrerror(err));
        return 2;
    }
    lua_pushstring(L, hp->h_name);
    inet_pushresolved(L, hp);
    return 2;
}

/*-------------------------------------------------------------------------*\
* Returns all information provided by the resolver given a host name
* or ip address
\*-------------------------------------------------------------------------*/
static int inet_global_toip(lua_State *L)
{
    const char *address = luaL_checkstring(L, 1);
    struct hostent *hp = NULL; 
    int err = inet_gethost(address, &hp);
    if (err != IO_DONE) {
        lua_pushnil(L);
        lua_pushstring(L, socket_hoststrerror(err));
        return 2;
    }
    lua_pushstring(L, inet_ntoa(*((struct in_addr *) hp->h_addr)));
    inet_pushresolved(L, hp);
    return 2;
}


/*-------------------------------------------------------------------------*\
* Gets the host name
\*-------------------------------------------------------------------------*/
static int inet_global_gethostname(lua_State *L)
{
    char name[257];
    name[256] = '\0';
    if (gethostname(name, 256) < 0) {
        lua_pushnil(L);
        lua_pushstring(L, "gethostname failed");
        return 2;
    } else {
        lua_pushstring(L, name);
        return 1;
    }
}



/*=========================================================================*\
* Lua methods
\*=========================================================================*/
/*-------------------------------------------------------------------------*\
* Retrieves socket peer name
\*-------------------------------------------------------------------------*/
int inet_meth_getpeername(lua_State *L, p_socket ps)
{
    struct sockaddr_in peer;
    socklen_t peer_len = sizeof(peer);
    if (getpeername(*ps, (SA *) &peer, &peer_len) < 0) {
        lua_pushnil(L);
        lua_pushstring(L, "getpeername failed");
    } else {
        lua_pushstring(L, inet_ntoa(peer.sin_addr));
        lua_pushnumber(L, ntohs(peer.sin_port));
    }
    return 2;
}

/*-------------------------------------------------------------------------*\
* Retrieves socket local name
\*-------------------------------------------------------------------------*/
int inet_meth_getsockname(lua_State *L, p_socket ps)
{
    struct sockaddr_in local;
    socklen_t local_len = sizeof(local);
    if (getsockname(*ps, (SA *) &local, &local_len) < 0) {
        lua_pushnil(L);
        lua_pushstring(L, "getsockname failed");
    } else {
        lua_pushstring(L, inet_ntoa(local.sin_addr));
        lua_pushnumber(L, ntohs(local.sin_port));
    }
    return 2;
}

/*=========================================================================*\
* Internal functions
\*=========================================================================*/
/*-------------------------------------------------------------------------*\
* Passes all resolver information to Lua as a table
\*-------------------------------------------------------------------------*/
static void inet_pushresolved(lua_State *L, struct hostent *hp)
{
    char **alias;
    struct in_addr **addr;
    int i, resolved;
    lua_newtable(L); resolved = lua_gettop(L);
    lua_pushstring(L, "name");
    lua_pushstring(L, hp->h_name);
    lua_settable(L, resolved);
    lua_pushstring(L, "ip");
    lua_pushstring(L, "alias");
    i = 1;
    alias = hp->h_aliases;
    lua_newtable(L);
    if (alias) {
        while (*alias) {
            lua_pushnumber(L, i);
            lua_pushstring(L, *alias);
            lua_settable(L, -3);
            i++; alias++;
        }
    }
    lua_settable(L, resolved);
    i = 1;
    lua_newtable(L);
    addr = (struct in_addr **) hp->h_addr_list;
    if (addr) {
        while (*addr) {
            lua_pushnumber(L, i);
            lua_pushstring(L, inet_ntoa(**addr));
            lua_settable(L, -3);
            i++; addr++;
        }
    }
    lua_settable(L, resolved);
}

/*-------------------------------------------------------------------------*\
* Tries to create a new inet(6) socket
\*-------------------------------------------------------------------------*/
const char *inet_trycreate(p_socket ps, int type, short domain) {
    return socket_strerror(socket_create(ps, domain, type, 0));
}

/*-------------------------------------------------------------------------*\
* Tries to connect to remote address (address, port)
\*-------------------------------------------------------------------------*/
const char *inet_tryconnect(p_socket ps, const char *address, 
        unsigned short port, p_timeout tm, short family)
{

   struct addrinfo *result = NULL, *rp = NULL;
    struct addrinfo hints;
    char portchar[12];
    int err;

    memset(&hints, 0, sizeof(hints));
    memset(&portchar, 0, sizeof(portchar));
    snprintf(portchar, 12, "%i", port);

    hints.ai_family   = family;
    hints.ai_protocol = 0;

    hints.ai_flags = AI_ADDRCONFIG;

    /* gai can take x.x.x.x, a 32-bit number, ipv6 format, or hostname */
    err = socket_getaddrinfo(address, portchar, &hints, &result);
    if (err != 0) { 
        if (result) socket_freeaddrinfo(result);
        return socket_gai_strerror(err);
    };

    /* Try connecting to the addresses one at a time - finish at the first successful one */
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        err = socket_connect(ps, rp->ai_addr, rp->ai_addrlen, tm);
        if (err == 0) 
            break;                  /* Success */
    };

    if (err != IO_DONE) socket_destroy(ps);
    if (result) socket_freeaddrinfo(result);
    return socket_strerror(err); 
}

/*-------------------------------------------------------------------------*\
* Tries to bind socket to (address, port, family); defaulting to AF_INET)
\*-------------------------------------------------------------------------*/
const char *inet_trybind(p_socket ps, const char *address, unsigned short port, short family)
{
    struct addrinfo *result = NULL, *rp = NULL;
    struct addrinfo hints;
    char portchar[12];
    int err, wildcard;

    memset(&hints, 0, sizeof(hints));
    memset(&portchar, 0, sizeof(portchar));
    snprintf(portchar, 12, "%i", port);

    /* We want wildcard addresses if "*" is specified as the host */
    wildcard = strcmp("*", address);

    hints.ai_family   = family;
    hints.ai_protocol = 0;

    hints.ai_flags = (wildcard == 0 ? AI_PASSIVE : 0) | AI_NUMERICSERV | AI_ADDRCONFIG;

    /* gai can take x.x.x.x, a 32-bit number, ipv6 format, or hostname */
    err = socket_getaddrinfo((wildcard == 0 ? NULL : address), portchar, &hints, &result);
    if (err != 0) { 
        if (result) socket_freeaddrinfo(result);
        return socket_gai_strerror(err);
    };


    /* Try binding to the addresses one at a time - finish at the first successful one */
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        err = socket_bind(ps, rp->ai_addr, rp->ai_addrlen);
        if (err == 0) 
            break;                  /* Success */
    };

    if (err != IO_DONE) socket_destroy(ps);
    if (result) socket_freeaddrinfo(result);
    return socket_strerror(err); 
}

/*-------------------------------------------------------------------------*\
* Some systems do not provide this so that we provide our own. It's not
* marvelously fast, but it works just fine.
\*-------------------------------------------------------------------------*/
#ifdef INET_ATON
int inet_aton(const char *cp, struct in_addr *inp)
{
    unsigned int a = 0, b = 0, c = 0, d = 0;
    int n = 0, r;
    unsigned long int addr = 0;
    r = sscanf(cp, "%u.%u.%u.%u%n", &a, &b, &c, &d, &n);
    if (r == 0 || n == 0) return 0;
    cp += n;
    if (*cp) return 0;
    if (a > 255 || b > 255 || c > 255 || d > 255) return 0;
    if (inp) {
        addr += a; addr <<= 8;
        addr += b; addr <<= 8;
        addr += c; addr <<= 8;
        addr += d;
        inp->s_addr = htonl(addr);
    }
    return 1;
}
#endif
