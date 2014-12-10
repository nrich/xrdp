/**
 * xrdp: A Remote Desktop Protocol server.
 *
 * Copyright (C) Jay Sorg 2004-2013
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * libxup main file
 */

#include "nx-xup.h"
#include "log.h"

#define LOG_LEVEL 1
#define LLOG(_level, _args) \
    do { if (_level < LOG_LEVEL) { g_write _args ; } } while (0)
#define LLOGLN(_level, _args) \
    do { if (_level < LOG_LEVEL) { g_writeln _args ; } } while (0)


//#define FREENX
#define EXTERNAL_X11RDP

#ifdef FREENX
#define PORT_OFFSET 1990
#else
#define PORT_OFFSET 1000
#endif

#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <signal.h>

#include <sys/socket.h>
#include <sys/un.h>

#include <pwd.h>

#define NX_SSH_TYPE_DSS 1
#define NX_SSH_TYPE_RSA 2

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX    108
#endif

static const char nx_default_private_key[] = "-----BEGIN DSA PRIVATE KEY-----\n"
                "MIIBuwIBAAKBgQCXv9AzQXjxvXWC1qu3CdEqskX9YomTfyG865gb4D02ZwWuRU/9\n"
                "C3I9/bEWLdaWgJYXIcFJsMCIkmWjjeSZyTmeoypI1iLifTHUxn3b7WNWi8AzKcVF\n"
                "aBsBGiljsop9NiD1mEpA0G+nHHrhvTXz7pUvYrsrXcdMyM6rxqn77nbbnwIVALCi\n"
                "xFdHZADw5KAVZI7r6QatEkqLAoGBAI4L1TQGFkq5xQ/nIIciW8setAAIyrcWdK/z\n"
                "5/ZPeELdq70KDJxoLf81NL/8uIc4PoNyTRJjtT3R4f8Az1TsZWeh2+ReCEJxDWgG\n"
                "fbk2YhRqoQTtXPFsI4qvzBWct42WonWqyyb1bPBHk+JmXFscJu5yFQ+JUVNsENpY\n"
                "+Gkz3HqTAoGANlgcCuA4wrC+3Cic9CFkqiwO/Rn1vk8dvGuEQqFJ6f6LVfPfRTfa\n"
                "QU7TGVLk2CzY4dasrwxJ1f6FsT8DHTNGnxELPKRuLstGrFY/PR7KeafeFZDf+fJ3\n"
                "mbX5nxrld3wi5titTnX+8s4IKv29HJguPvOK/SI7cjzA+SqNfD7qEo8CFDIm1xRf\n"
                "8xAPsSKs6yZ6j1FNklfu\n"
                "-----END DSA PRIVATE KEY-----\n";


static void session_send_command(struct mod *v, const char *cmd) {
    ssh_session session = v->session;
    ssh_channel channel = v->channel;

    channel_write(channel, cmd, g_strlen(cmd));

    ssh_set_fd_towrite(session);
    channel_write(channel, "\n", 1);
}

static int get_response_line(struct mod *v, int timeout_in_seconds, char *output) {
    struct timeval timeout;
    ssh_channel ch[2];
    ssh_buffer buffer;
    int len;
    int is_stderr;

    timeout.tv_sec = timeout_in_seconds;
    timeout.tv_usec = 0;
    ch[0] = v->channel;
    ch[1] = NULL;
    channel_select(ch, NULL, NULL, &timeout);

    is_stderr = 0;
    while (is_stderr <= 1) {
        len = channel_poll(v->channel, is_stderr);
        if (len == SSH_ERROR)
        {
            return 0;
        }
        if (len > 0)
            break;
        is_stderr++;
    }

    if (is_stderr > 1)
        return 0;

    buffer = buffer_new();
    len = channel_read_buffer(v->channel, buffer, len, is_stderr);
    if (len <= 0) {
        return 0;
    }

    if (len > 0) {
        strncat(output, (const char*) buffer_get(buffer), len);
    }

    buffer_free(buffer);
    return 1;
}

static int get_expected_response(struct mod *v, int expected_code) {
    char output[1024];
    int response_code = -1;
    char *curLine;

    output[0] = '\0';

    v->server_msg(v, "Enter get_response_line loop", 1);
    while (get_response_line(v, 1, output)) {
        v->server_msg(v, "Doing get_response_line loop", 1);
        v->server_msg(v, output, 1);

        curLine = output;
        while (curLine) {
            char *nextLine = g_strchr(curLine, '\n');

            if (sscanf(curLine, "NX> %i ", &response_code) > 0) {
                if (response_code == expected_code)
                    return 1;
            }

            if (nextLine)
                *nextLine = '\0';

            curLine = nextLine ? (nextLine + 1) : NULL;
        }

        output[0] = '\0';
    }

    return 0;
}

static int get_session(struct mod *v, char *ip, char *sessiontoken) {
    char output[10240];
    char username[128];
    int response_code = -1;
    char *curLine;
    int count = 10;
    int display;

#ifdef FREENX
    char server[128];
#endif

    output[0] = '\0';

    v->server_msg(v, "Enter get_session loop", 1);
    while (get_response_line(v, 1, output)) {
        v->server_msg(v, "Doing get_session loop", 1);
        v->server_msg(v, output, 1);

        curLine = output;
        while (curLine) {
            char *nextLine = g_strchr(curLine, '\n');

            if (sscanf(curLine, "NX> %i ", &response_code) > 0) {
                if (response_code == 105)
                    return 1;
            }

#ifdef FREENX
            if (sscanf(curLine, "%s %d %s %s %s", server, &display, username, ip, sessiontoken) > 0) {
#else
            if (sscanf(curLine, "%d %s %s %s", &display, username, ip, sessiontoken) > 0) {
#endif

                v->server_msg(v, "Found session name", 1);
                v->server_msg(v, sessiontoken, 1);

                v->display = display;
                //v->sessiontoken = g_strdup(sessiontoken);
            }

            if (nextLine)
                *nextLine = '\0';

            curLine = nextLine ? (nextLine + 1) : NULL;
        }

        output[0] = '\0';
    }

    return 0;
}

int get_session_info(struct mod *v, char *sessionid, char *cookie) {
    char output[10240];
    int response_code = -1;
    char *curLine;
    int count = 10;
    int status;

    output[0] = '\0';

    v->server_msg(v, "Enter get_session_info loop", 1);
    while (get_response_line(v, 1, output)) {
        v->server_msg(v, "Doing get_session_info loop", 1);
        v->server_msg(v, output, 1);

        curLine = output;
        while (curLine) {
            char *nextLine = g_strchr(curLine, '\n');

            if (sscanf(curLine, "NX> %i ", &response_code) > 0) {
                if (response_code == 105)
                    return 1;
            }

            if (sscanf(curLine, "NX> %i ", &status) > 0) {
                if (status == 700) {
                    if (sscanf(curLine, "NX> 700 Session id: %s", sessionid) > 0) {
                        //v->server_msg(v, "Found session ID %s", sessionid);
                        //v->sessionid = g_strdup(sessionid);
                    }
                } else if (status == 701) {
                    if (sscanf(curLine, "NX> 701 Proxy cookie: %32s", cookie) > 0) {
                        //v->server_msg(v, "Found session cookie %s", cookie);
                        //v->cookie = g_strdup(cookie);
                    }
                } else if (status == 705) {
                    if (sscanf(curLine, "NX> 705 Session display: %d", &v->display) > 0) {
                        //v->server_msg(v, "Found session cookie %s", cookie);
                        //v->cookie = g_strdup(cookie);
                    }

                } else if (status == 105) {
                    return 1;
                }
            }

            if (nextLine)
                *nextLine = '\0';

            curLine = nextLine ? (nextLine + 1) : NULL;
        }

        output[0] = '\0';
    }

    return 0;
}

int get_canvas_display(struct mod *mod, char display[], size_t buffersize) {
#ifdef EXTERNAL_X11RDP
    g_snprintf(display, buffersize-1, ":%d", atoi(mod->port) - 6200);
#else
    g_snprintf(display, buffersize-1, ":%d", mod->display - PORT_OFFSET);
#endif


    return 1;
}

int send_disconnect(int nxdisplay) {
    struct sockaddr_un sa;

    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;

    g_snprintf(sa.sun_path, UNIX_PATH_MAX-1, "/tmp/xrdp_disconnect_display_%d", nxdisplay);
    if (access(sa.sun_path, F_OK) == 0)
    {
        int sck = socket(PF_UNIX, SOCK_DGRAM, 0);
        size_t len = sizeof(sa);
        sendto(sck, "sig", 4, 0, (struct sockaddr*)&sa, len);
    }
    else
    {
        log_message(LOG_LEVEL_INFO, "Failed to send disconnect to %s", sa.sun_path);
        return 0;
    }
    return 1;
}

int start_nxproxy(struct mod *mod, char *sessionid, char *cookie, uid_t uid) {
    pid_t nxproxy = fork();

    if (nxproxy > 0) {
        mod->server_msg(mod, "Forked NXProxy", 1);
    } else if (nxproxy == 0) {
        char sessionstash[512];
        char display[32];

        get_canvas_display(mod, display, sizeof display);

        g_snprintf(sessionstash, sizeof(sessionstash)-1, "nx,session=%s,cookie=%s,id=%s,shmem=1,shpix=1,connect=%s:%d", mod->username, cookie, sessionid, "127.0.0.1", mod->display);
        mod->server_msg(mod, sessionstash, 1);

        //setuid(uid);

        setenv("DISPLAY", display, 1);
        execl("/usr/bin/nxproxy", "/usr/bin/nxproxy", "-S", sessionstash, NULL);
    } else {
        mod->server_msg(mod, "NXProxy fork failed", 1);
        return 0;
    }

    return 1;
}

int start_x11rdp(struct mod *mod, uid_t uid) {
    char disconnect_socket[128];

    if (access(disconnect_socket, F_OK) != -1) {
        mod->server_msg(mod, "X11rdp already running", 1);
        return 1;
    } else {
        pid_t x11rdp = fork();

        if (x11rdp > 1) {
            mod->server_msg(mod, "Forked X11rdp", 1);
        } else if (x11rdp == 0) {
            char geometry[32];
            char display[32];

            setsid();
            signal(SIGHUP, SIG_IGN);

            setuid(uid);

            g_snprintf(geometry, sizeof(geometry)-1, "%dx%d", mod->width, mod->height);
            get_canvas_display(mod, display, sizeof display);

            execl("/usr/bin/X11rdp", "/usr/bin/X11rdp", display, "-geometry", geometry, "-depth", "24", "-bs", "-ac", "-nolisten", "tcp", NULL);
        } else {
            mod->server_msg(mod, "X11rdp fork failed", 0);
            return 0;
        }

        return 1;
    }
}

int resize_nxproxy(struct mod *mod, uid_t uid) {
    pid_t xwit = fork();

    if (xwit > 0) {
        wait();
    } else if (xwit == 0) {
        char display[32];
        char width[32];
        char height[32];

        //setuid(uid);

        g_snprintf(width, sizeof(width)-1, "%d", mod->width);
        g_snprintf(height, sizeof(height)-1, "%d", mod->height);
        get_canvas_display(mod, display, sizeof display);

        execl("/usr/bin/xwit", "/usr/bin/xwit", "-display", display, "-all", "-resize", width, height, NULL);
    } else {
        return 0;
    }

    return 1;
}


/******************************************************************************/
/* returns error */
int DEFAULT_CC
lib_recv(struct mod *mod, char *data, int len)
{
    int rcvd;

    if (mod->sck_closed)
    {
        return 1;
    }

    while (len > 0)
    {
        rcvd = g_tcp_recv(mod->sck, data, len, 0);

        if (rcvd == -1)
        {
            if (g_tcp_last_error_would_block(mod->sck))
            {
                if (mod->server_is_term(mod))
                {
                    return 1;
                }

                g_tcp_can_recv(mod->sck, 10);
            }
            else
            {
                return 1;
            }
        }
        else if (rcvd == 0)
        {
            mod->sck_closed = 1;
            return 1;
        }
        else
        {
            data += rcvd;
            len -= rcvd;
        }
    }

    return 0;
}

/*****************************************************************************/
/* returns error */
int DEFAULT_CC
lib_send(struct mod *mod, char *data, int len)
{
    int sent;

    if (mod->sck_closed)
    {
        return 1;
    }

    while (len > 0)
    {
        sent = g_tcp_send(mod->sck, data, len, 0);

        if (sent == -1)
        {
            if (g_tcp_last_error_would_block(mod->sck))
            {
                if (mod->server_is_term(mod))
                {
                    return 1;
                }

                g_tcp_can_send(mod->sck, 10);
            }
            else
            {
                return 1;
            }
        }
        else if (sent == 0)
        {
            mod->sck_closed = 1;
            return 1;
        }
        else
        {
            data += sent;
            len -= sent;
        }
    }

    return 0;
}

/******************************************************************************/
/* return error */
int DEFAULT_CC
lib_mod_start(struct mod *mod, int w, int h, int bpp)
{
    LIB_DEBUG(mod, "in lib_mod_start");
    mod->width = w;
    mod->height = h;
    mod->bpp = bpp;
    LIB_DEBUG(mod, "out lib_mod_start");
    return 0;
}

/******************************************************************************/
static int APP_CC
lib_mod_log_peer(struct mod *mod)
{
    int my_pid;
    int pid;
    int uid;
    int gid;

    my_pid = g_getpid();
    if (g_sck_get_peer_cred(mod->sck, &pid, &uid, &gid) == 0)
    {
        log_message(LOG_LEVEL_INFO, "lib_mod_log_peer: xrdp_pid=%d connected "
                    "to X11rdp_pid=%d X11rdp_uid=%d X11rdp_gid=%d "
                    "client_ip=%s client_port=%s",
                    my_pid, pid, uid, gid,
                    mod->client_info.client_addr,
                    mod->client_info.client_port);
    }
    else
    {
        log_message(LOG_LEVEL_ERROR, "lib_mod_log_peer: g_sck_get_peer_cred "
                    "failed");
    }
    return 0;
}

/******************************************************************************/
/* return error */
int DEFAULT_CC
lib_mod_connect(struct mod *mod)
{
    int error;
    int len;
    int i;
    int index;
    int use_uds;
    struct stream *s;
    char con_port[256];
    int retry = 0;
    int send_error = 0;

    int rc = 0;
    ssh_private_key privkey;
    ssh_public_key pubkey;
    ssh_string pubkeystr;
    unsigned int nbytes;
    char tmpfile[L_tmpnam + 1];
    char pidfile[128];
    char ip[16];

    char cookie[33];
    char sessionid[128];
    char sessiontoken[128];

    struct passwd pwd;
    struct passwd *pwdresult;
    char pwdbuffer[16384];

    sessiontoken[0] = '\0';

    mod->server_msg(mod, "NX started connection", 0);

    mod->session = ssh_new();
    if (mod->session == NULL) {
        mod->server_msg(mod, "Failed to create SSH session", 0);
        return 1;
    }

    ssh_options_set(mod->session, SSH_OPTIONS_HOST, "localhost");
    ssh_options_set(mod->session, SSH_OPTIONS_USER, "nx");

    if (tmpnam(tmpfile) == NULL) {
        mod->server_msg(mod, "Failed to create temporary private key file", 0);
        return 1;
    } else {
        FILE *keyfile = fopen(tmpfile, "w");
        size_t keylen = sizeof(nx_default_private_key);
        if (!keyfile) {
            mod->server_msg(mod, "Failed to open temporary private key file", 0);
            return 1;
        }

        if (fwrite(nx_default_private_key, keylen-1, 1, keyfile) != 1) {
            mod->server_msg(mod, "Failed to write to temporary private key file", 0);
            return 1;
        }

        fclose(keyfile);

        mod->server_msg(mod, "Starting private key", 1);
        privkey = privatekey_from_file(mod->session, tmpfile, NX_SSH_TYPE_DSS, "");
        mod->server_msg(mod, "Got private key from file", 1);
        pubkey = publickey_from_privatekey(privkey);
        mod->server_msg(mod, "Got public key from private key", 1);
        pubkeystr = publickey_to_string(pubkey);
        mod->server_msg(mod, "Got public key string from public key", 1);
        publickey_free(pubkey);

        unlink(tmpfile);
    }

    rc = ssh_connect(mod->session);
    if (rc != SSH_OK) {
        //v->server_msg(v, "Failed to connect to SSH server %s", ssh_get_error(session));
        mod->server_msg(mod, "Failed to connect to SSH server", 0);
        ssh_free(mod->session);
        return 1;
    } else {
        mod->server_msg(mod, "Connected to SSH server", 1);
    }


    rc = ssh_userauth_pubkey(mod->session, NULL, pubkeystr, privkey);

    string_free(pubkeystr);
    privatekey_free(privkey);

    if (rc != SSH_AUTH_SUCCESS) {
        //v->server_msg(v, "Failed to auth to SSH server %s", ssh_get_error(session));
        mod->server_msg(mod, "Failed to auth to SSH server", 0);
        ssh_free(mod->session);
        return 1;
    } else {
        mod->server_msg(mod, "Authenticated to SSH server", 1);
    }

    mod->channel = ssh_channel_new(mod->session);
    if (mod->channel == NULL) {
        //v->server_msg(v, "Error creating channel %s", ssh_get_error(session));
        mod->server_msg(mod, "Error creating channel", 0);
        ssh_free(mod->session);
        return 1;
    } else {
        mod->server_msg(mod, "Created channel", 1);
    }

    rc = ssh_channel_open_session(mod->channel);
    if (rc != SSH_OK) {
        ssh_channel_free(mod->channel);
        //v->server_msg(v, "Error opening channel: %s\n", ssh_get_error(session));
        mod->server_msg(mod, "Error opening channel", 0);
        return 1;
    } else {
        mod->server_msg(mod, "Opened channel", 1);
    }

    channel_request_shell(mod->channel);

    session_send_command(mod, "HELLO NXCLIENT - Version 3.5.0");
    mod->server_msg(mod, "Sent hello", 1);
    if (!get_expected_response(mod, 105)) {
        mod->server_msg(mod, "Hello to NX server failed", 0);
        return 1;
    } else {
        mod->server_msg(mod, "Said hello", 1);
    }

    session_send_command(mod, "SET SHELL_MODE SHELL");
    if (!get_expected_response(mod, 105)) {
        mod->server_msg(mod, "Set shell mode failed", 0);
        return 1;
    } else {
        mod->server_msg(mod, "Set shell mode", 1);
    }

    session_send_command(mod, "SET AUTH_MODE PASSWORD");
    if (!get_expected_response(mod, 105)) {
        mod->server_msg(mod, "Set auth mode failed", 0);
        return 1;
    } else {
        mod->server_msg(mod, "Set auth mode", 1);
    }

    session_send_command(mod, "login");
    if (!get_expected_response(mod, 101)) {
        mod->server_msg(mod, "Login command failed", 0);
        return 1;
    } else {
        mod->server_msg(mod, "Login", 1);
    }

    session_send_command(mod, mod->username);
    if (!get_expected_response(mod, 102)) {
        mod->server_msg(mod, "Sending username failed", 0);
        return 1;
    } else {
        mod->server_msg(mod, "Sent username", 1);
    }

    session_send_command(mod, mod->password);
    if (!get_expected_response(mod, 105)) {
        mod->server_msg(mod, "Authentication failed", 0);
        return 1;
    } else {
        mod->server_msg(mod, "Authentication successful", 1);
    }

#ifdef FREENX
    session_send_command(mod, "listsession --all");
#else
    session_send_command(mod, "listsession");
#endif

    if (!get_session(mod, ip, sessiontoken)) {
        mod->server_msg(mod, "Session listing failed", 0);
        return 1;
    } else {
        mod->server_msg(mod, "Listed sessions", 1);
    }

    getpwnam_r(mod->username, &pwd, pwdbuffer, sizeof(pwdbuffer), &pwdresult);
    if (pwdresult == NULL) {
        mod->server_msg(mod, "Uid lookup failed", 0);
        return 1;
    }

    if (sessiontoken[0] == '\0') {
        pid_t x11rdp = 0;
        char sessioncommand[1024];

        mod->server_msg(mod, "Creating new NX session", 0);

        g_snprintf(sessioncommand, 1023, "startsession --session=\"%s\" --screeninfo=\"%dx%dx24+render\" --type=\"unix-application\" --application=\"startxfce4\" --geometry=\"%dx%d\" --client=\"linux\" --cache=\"16M\" --images=\"64M\" --link=\"lan\" --encryption=\"0\" --render=\"1\" --backingstore=\"1\" --resize=\"1\"", mod->username, mod->width, mod->height, mod->width, mod->height);
        session_send_command(mod, sessioncommand);
        get_session_info(mod, sessionid, cookie);

#ifndef EXTERNAL_X11RDP
        if (!start_x11rdp(mod, pwd.pw_uid)) {
            return 1;
        }
#endif

        if (!start_nxproxy(mod, sessionid, cookie, pwd.pw_uid)) {
            return 1;
        }
    } else {
        int do_restore = 1;
        char display[32];
        char geometry[32];

#ifdef EXTERNAL_X11RDP
        send_disconnect(atoi(mod->port)-6200);
#else
        send_disconnect(mod->display-PORT_OFFSET);
#endif

        get_canvas_display(mod, display, sizeof display);
        g_snprintf(geometry, sizeof(geometry)-1, "%dx%d", mod->width, mod->height);

        if (ip[0] == '-') {
            /* no session */
            do_restore = 1;
        } else if (g_strcmp(ip, "127.0.0.1") == 0) {
            if (!resize_nxproxy(mod, pwd.pw_uid)) {
                return 1;
            }

            /* local session already running */
            mod->server_msg(mod, "NXProxy already running", 1);
            do_restore = 0;
        } else {
            /* another remote session */
            char disconnectcommand[1024];

            g_snprintf(disconnectcommand, 1023, "disconnect --sessionid=\"%s\"", sessiontoken);
            session_send_command(mod, disconnectcommand);
            if (!get_expected_response(mod, 105)) {
                mod->server_msg(mod, "Disconnect failed", 0);
                return 1;
            } else {
                mod->server_msg(mod, "Disconnect existing session", 1);
            }

            do_restore = 1;
        }

        if (do_restore) {
            char sessioncommand[1024];

            mod->server_msg(mod, "Resuming NX session", 0);

            g_snprintf(sessioncommand, 1023, "restoresession --session=\"%s\" --id=\"%s\" --type=\"unix-application\" --app=\"startxfce4\" --geometry=\"%dx%d\" --client=\"linux\" --cache=\"16M\" --images=\"64M\" --link=\"lan\" --encryption=\"0\" --render=\"1\" --backingstore=\"1\" --resize=\"1\"", mod->username, sessiontoken, mod->width, mod->height);
            session_send_command(mod, sessioncommand);
            get_session_info(mod, sessionid, cookie);

#ifndef EXTERNAL_X11RDP
            if (!start_x11rdp(mod, pwd.pw_uid)) {
                return 1;
            }
#endif

            if (!start_nxproxy(mod, sessionid, cookie, pwd.pw_uid)) {
                return 1;
            }
        } else {
            mod->server_msg(mod, "Connecting to existing session", 0);
        }
    }

    session_send_command(mod, "bye");
    if (!get_expected_response(mod, 999)) {
        mod->server_msg(mod, "Goodbye failed", 0);
        return 1;
    } else {
        mod->server_msg(mod, "Sent goodbye", 1);
    }

    ssh_channel_close(mod->channel);
    ssh_channel_send_eof(mod->channel);
    ssh_channel_free(mod->channel);

    ssh_disconnect(mod->session);
    ssh_free(mod->session);

    LIB_DEBUG(mod, "in lib_mod_connect");
    /* clear screen */
    mod->server_begin_update(mod);
    mod->server_set_fgcolor(mod, 0);
    mod->server_fill_rect(mod, 0, 0, mod->width, mod->height);
    mod->server_end_update(mod);
    mod->server_msg(mod, "started connecting", 0);

    /* only support 8, 15, 16, and 24 bpp connections from rdp client */
    if (mod->bpp != 8 && mod->bpp != 15 && mod->bpp != 16 && mod->bpp != 24)
    {
        mod->server_msg(mod,
                        "error - only supporting 8, 15, 16, and 24 bpp rdp connections", 0);
        LIB_DEBUG(mod, "out lib_mod_connect error");
        return 1;
    }

    if (g_strcmp(mod->ip, "") == 0)
    {
        mod->server_msg(mod, "error - no ip set", 0);
        LIB_DEBUG(mod, "out lib_mod_connect error");
        return 1;
    }

    make_stream(s);

#ifdef EXTERNAL_X11RDP
    g_snprintf(con_port, 255, "%s", mod->port);
#else
    g_snprintf(con_port, 255, "%d", 6200 + mod->display - PORT_OFFSET);
#endif
    use_uds = 0;

    if (con_port[0] == '/')
    {
        use_uds = 1;
    }

    mod->sck_closed = 0;
    i = 0;

RECONNECT:
    while (1)
    {
        if (use_uds)
        {
            mod->sck = g_tcp_local_socket();
        }
        else
        {
            mod->sck = g_tcp_socket();
            g_tcp_set_non_blocking(mod->sck);
            g_tcp_set_no_delay(mod->sck);
        }

        /* mod->server_msg(mod, "connecting...", 0); */

        if (use_uds)
        {
            error = g_tcp_local_connect(mod->sck, con_port);
        }
        else
        {
            error = g_tcp_connect(mod->sck, mod->ip, con_port);
        }

        if (error == -1)
        {
            if (g_tcp_last_error_would_block(mod->sck))
            {
                error = 0;
                index = 0;

                while (!g_tcp_can_send(mod->sck, 100))
                {
                    index++;

                    if ((index >= 30) || mod->server_is_term(mod))
                    {
                        mod->server_msg(mod, "connect timeout", 0);
                        error = 1;
                        break;
                    }
                }
            }
            else
            {
                /* mod->server_msg(mod, "connect error", 0); */
            }
        }

        if (error == 0)
        {
            break;
        }

        g_tcp_close(mod->sck);
        mod->sck = 0;
        i++;

        if (i >= 20)
        {
            mod->server_msg(mod, "connection problem, giving up", 0);
            break;
        }

        g_sleep(500);
    }

    if (error == 0)
    {
        if (use_uds)
        {
            lib_mod_log_peer(mod);
        }
    }

    if (error == 0)
    {
        /* send version message */
        init_stream(s, 8192);
        s_push_layer(s, iso_hdr, 4);
        out_uint16_le(s, 103);
        out_uint32_le(s, 301);
        out_uint32_le(s, 0);
        out_uint32_le(s, 0);
        out_uint32_le(s, 0);
        out_uint32_le(s, 1);
        s_mark_end(s);
        len = (int)(s->end - s->data);
        s_pop_layer(s, iso_hdr);
        out_uint32_le(s, len);
        lib_send(mod, s->data, len);
    }

    if (error == 0)
    {
        /* send screen size message */
        init_stream(s, 8192);
        s_push_layer(s, iso_hdr, 4);
        out_uint16_le(s, 103);
        out_uint32_le(s, 300);
        out_uint32_le(s, mod->width);
        out_uint32_le(s, mod->height);
        out_uint32_le(s, mod->bpp);
        out_uint32_le(s, 0);
        s_mark_end(s);
        len = (int)(s->end - s->data);
        s_pop_layer(s, iso_hdr);
        out_uint32_le(s, len);
        lib_send(mod, s->data, len);
    }

    if (error == 0)
    {
        /* send invalidate message */
        init_stream(s, 8192);
        s_push_layer(s, iso_hdr, 4);
        out_uint16_le(s, 103);
        out_uint32_le(s, 200);
        /* x and y */
        i = 0;
        out_uint32_le(s, i);
        /* width and height */
        i = ((mod->width & 0xffff) << 16) | mod->height;
        out_uint32_le(s, i);
        out_uint32_le(s, 0);
        out_uint32_le(s, 0);
        s_mark_end(s);
        len = (int)(s->end - s->data);
        s_pop_layer(s, iso_hdr);
        out_uint32_le(s, len);
        send_error = lib_send(mod, s->data, len);
    }

    if (send_error) {
        if (retry < 50) {
            g_tcp_close(mod->sck);
            mod->server_msg(mod, "Doing a retry", 0);
            retry++;
            g_sleep(1000);
            goto RECONNECT;
        }

        error = send_error;
    }

    free_stream(s);

    if (error != 0)
    {
        mod->server_msg(mod, "some problem", 0);
        LIB_DEBUG(mod, "out lib_mod_connect error");
        return 1;
    }
    else
    {
        mod->server_msg(mod, "connected ok", 0);
        mod->sck_obj = g_create_wait_obj_from_socket(mod->sck, 0);
    }

    LIB_DEBUG(mod, "out lib_mod_connect");
    return 0;
}

/******************************************************************************/
/* return error */
int DEFAULT_CC
lib_mod_event(struct mod *mod, int msg, tbus param1, tbus param2,
              tbus param3, tbus param4)
{
    struct stream *s;
    int len;
    int key;
    int rv;

    LIB_DEBUG(mod, "in lib_mod_event");
    make_stream(s);

    if ((msg >= 15) && (msg <= 16)) /* key events */
    {
        key = param2;

        if (key > 0)
        {
            if (key == 65027) /* altgr */
            {
                if (mod->shift_state)
                {
                    g_writeln("special");
                    /* fix for mstsc sending left control down with altgr */
                    /* control down / up
                    msg param1 param2 param3 param4
                    15  0      65507  29     0
                    16  0      65507  29     49152 */
                    init_stream(s, 8192);
                    s_push_layer(s, iso_hdr, 4);
                    out_uint16_le(s, 103);
                    out_uint32_le(s, 16); /* key up */
                    out_uint32_le(s, 0);
                    out_uint32_le(s, 65507); /* left control */
                    out_uint32_le(s, 29); /* RDP scan code */
                    out_uint32_le(s, 0xc000); /* flags */
                    s_mark_end(s);
                    len = (int)(s->end - s->data);
                    s_pop_layer(s, iso_hdr);
                    out_uint32_le(s, len);
                    lib_send(mod, s->data, len);
                }
            }

            if (key == 65507) /* left control */
            {
                mod->shift_state = msg == 15;
            }
        }
    }

    init_stream(s, 8192);
    s_push_layer(s, iso_hdr, 4);
    out_uint16_le(s, 103);
    out_uint32_le(s, msg);
    out_uint32_le(s, param1);
    out_uint32_le(s, param2);
    out_uint32_le(s, param3);
    out_uint32_le(s, param4);
    s_mark_end(s);
    len = (int)(s->end - s->data);
    s_pop_layer(s, iso_hdr);
    out_uint32_le(s, len);
    rv = lib_send(mod, s->data, len);
    free_stream(s);
    LIB_DEBUG(mod, "out lib_mod_event");
    return rv;
}

/******************************************************************************/
/* return error */
static int APP_CC
process_server_fill_rect(struct mod *mod, struct stream *s)
{
    int rv;
    int x;
    int y;
    int cx;
    int cy;

    in_sint16_le(s, x);
    in_sint16_le(s, y);
    in_uint16_le(s, cx);
    in_uint16_le(s, cy);
    rv = mod->server_fill_rect(mod, x, y, cx, cy);
    return rv;
}

/******************************************************************************/
/* return error */
static int APP_CC
process_server_screen_blt(struct mod *mod, struct stream *s)
{
    int rv;
    int x;
    int y;
    int cx;
    int cy;
    int srcx;
    int srcy;

    in_sint16_le(s, x);
    in_sint16_le(s, y);
    in_uint16_le(s, cx);
    in_uint16_le(s, cy);
    in_sint16_le(s, srcx);
    in_sint16_le(s, srcy);
    rv = mod->server_screen_blt(mod, x, y, cx, cy, srcx, srcy);
    return rv;
}

/******************************************************************************/
/* return error */
static int APP_CC
process_server_paint_rect(struct mod *mod, struct stream *s)
{
    int rv;
    int x;
    int y;
    int cx;
    int cy;
    int len_bmpdata;
    char *bmpdata;
    int width;
    int height;
    int srcx;
    int srcy;

    in_sint16_le(s, x);
    in_sint16_le(s, y);
    in_uint16_le(s, cx);
    in_uint16_le(s, cy);
    in_uint32_le(s, len_bmpdata);
    in_uint8p(s, bmpdata, len_bmpdata);
    in_uint16_le(s, width);
    in_uint16_le(s, height);
    in_sint16_le(s, srcx);
    in_sint16_le(s, srcy);
    rv = mod->server_paint_rect(mod, x, y, cx, cy,
                                bmpdata, width, height,
                                srcx, srcy);
    return rv;
}

/******************************************************************************/
/* return error */
static int APP_CC
process_server_set_clip(struct mod *mod, struct stream *s)
{
    int rv;
    int x;
    int y;
    int cx;
    int cy;

    in_sint16_le(s, x);
    in_sint16_le(s, y);
    in_uint16_le(s, cx);
    in_uint16_le(s, cy);
    rv = mod->server_set_clip(mod, x, y, cx, cy);
    return rv;
}

/******************************************************************************/
/* return error */
static int APP_CC
process_server_reset_clip(struct mod *mod, struct stream *s)
{
    int rv;

    rv = mod->server_reset_clip(mod);
    return rv;
}

/******************************************************************************/
/* return error */
static int APP_CC
process_server_set_fgcolor(struct mod *mod, struct stream *s)
{
    int rv;
    int fgcolor;

    in_uint32_le(s, fgcolor);
    rv = mod->server_set_fgcolor(mod, fgcolor);
    return rv;
}

/******************************************************************************/
/* return error */
static int APP_CC
process_server_set_bgcolor(struct mod *mod, struct stream *s)
{
    int rv;
    int bgcolor;

    in_uint32_le(s, bgcolor);
    rv = mod->server_set_bgcolor(mod, bgcolor);
    return rv;
}

/******************************************************************************/
/* return error */
static int APP_CC
process_server_set_opcode(struct mod *mod, struct stream *s)
{
    int rv;
    int opcode;

    in_uint16_le(s, opcode);
    rv = mod->server_set_opcode(mod, opcode);
    return rv;
}

/******************************************************************************/
/* return error */
static int APP_CC
process_server_set_pen(struct mod *mod, struct stream *s)
{
    int rv;
    int style;
    int width;

    in_uint16_le(s, style);
    in_uint16_le(s, width);
    rv = mod->server_set_pen(mod, style, width);
    return rv;
}

/******************************************************************************/
/* return error */
static int APP_CC
process_server_draw_line(struct mod *mod, struct stream *s)
{
    int rv;
    int x1;
    int y1;
    int x2;
    int y2;

    in_sint16_le(s, x1);
    in_sint16_le(s, y1);
    in_sint16_le(s, x2);
    in_sint16_le(s, y2);
    rv = mod->server_draw_line(mod, x1, y1, x2, y2);
    return rv;
}

/******************************************************************************/
/* return error */
static int APP_CC
process_server_set_cursor(struct mod *mod, struct stream *s)
{
    int rv;
    int x;
    int y;
    char cur_data[32 * (32 * 3)];
    char cur_mask[32 * (32 / 8)];

    in_sint16_le(s, x);
    in_sint16_le(s, y);
    in_uint8a(s, cur_data, 32 * (32 * 3));
    in_uint8a(s, cur_mask, 32 * (32 / 8));
    rv = mod->server_set_cursor(mod, x, y, cur_data, cur_mask);
    return rv;
}

/******************************************************************************/
/* return error */
static int APP_CC
process_server_create_os_surface(struct mod *mod, struct stream *s)
{
    int rv;
    int rdpid;
    int width;
    int height;

    in_uint32_le(s, rdpid);
    in_uint16_le(s, width);
    in_uint16_le(s, height);
    rv = mod->server_create_os_surface(mod, rdpid, width, height);
    return rv;
}

/******************************************************************************/
/* return error */
static int APP_CC
process_server_switch_os_surface(struct mod *mod, struct stream *s)
{
    int rv;
    int rdpid;

    in_uint32_le(s, rdpid);
    rv = mod->server_switch_os_surface(mod, rdpid);
    return rv;
}

/******************************************************************************/
/* return error */
static int APP_CC
process_server_delete_os_surface(struct mod *mod, struct stream *s)
{
    int rv;
    int rdpid;

    in_uint32_le(s, rdpid);
    rv = mod->server_delete_os_surface(mod, rdpid);
    return rv;
}

/******************************************************************************/
/* return error */
static int APP_CC
process_server_paint_rect_os(struct mod *mod, struct stream *s)
{
    int rv;
    int x;
    int y;
    int cx;
    int cy;
    int rdpid;
    int srcx;
    int srcy;

    in_sint16_le(s, x);
    in_sint16_le(s, y);
    in_uint16_le(s, cx);
    in_uint16_le(s, cy);
    in_uint32_le(s, rdpid);
    in_sint16_le(s, srcx);
    in_sint16_le(s, srcy);
    rv = mod->server_paint_rect_os(mod, x, y, cx, cy,
                                   rdpid, srcx, srcy);
    return rv;
}

/******************************************************************************/
/* return error */
static int APP_CC
process_server_set_hints(struct mod *mod, struct stream *s)
{
    int rv;
    int hints;
    int mask;

    in_uint32_le(s, hints);
    in_uint32_le(s, mask);
    rv = mod->server_set_hints(mod, hints, mask);
    return rv;
}

/******************************************************************************/
/* return error */
static int APP_CC
process_server_window_new_update(struct mod *mod, struct stream *s)
{
    int flags;
    int window_id;
    int title_bytes;
    int index;
    int bytes;
    int rv;
    struct rail_window_state_order rwso;

    g_memset(&rwso, 0, sizeof(rwso));
    in_uint32_le(s, window_id);
    in_uint32_le(s, rwso.owner_window_id);
    in_uint32_le(s, rwso.style);
    in_uint32_le(s, rwso.extended_style);
    in_uint32_le(s, rwso.show_state);
    in_uint16_le(s, title_bytes);

    if (title_bytes > 0)
    {
        rwso.title_info = g_malloc(title_bytes + 1, 0);
        in_uint8a(s, rwso.title_info, title_bytes);
        rwso.title_info[title_bytes] = 0;
    }

    in_uint32_le(s, rwso.client_offset_x);
    in_uint32_le(s, rwso.client_offset_y);
    in_uint32_le(s, rwso.client_area_width);
    in_uint32_le(s, rwso.client_area_height);
    in_uint32_le(s, rwso.rp_content);
    in_uint32_le(s, rwso.root_parent_handle);
    in_uint32_le(s, rwso.window_offset_x);
    in_uint32_le(s, rwso.window_offset_y);
    in_uint32_le(s, rwso.window_client_delta_x);
    in_uint32_le(s, rwso.window_client_delta_y);
    in_uint32_le(s, rwso.window_width);
    in_uint32_le(s, rwso.window_height);
    in_uint16_le(s, rwso.num_window_rects);

    if (rwso.num_window_rects > 0)
    {
        bytes = sizeof(struct rail_window_rect) * rwso.num_window_rects;
        rwso.window_rects = (struct rail_window_rect *)g_malloc(bytes, 0);

        for (index = 0; index < rwso.num_window_rects; index++)
        {
            in_uint16_le(s, rwso.window_rects[index].left);
            in_uint16_le(s, rwso.window_rects[index].top);
            in_uint16_le(s, rwso.window_rects[index].right);
            in_uint16_le(s, rwso.window_rects[index].bottom);
        }
    }

    in_uint32_le(s, rwso.visible_offset_x);
    in_uint32_le(s, rwso.visible_offset_y);
    in_uint16_le(s, rwso.num_visibility_rects);

    if (rwso.num_visibility_rects > 0)
    {
        bytes = sizeof(struct rail_window_rect) * rwso.num_visibility_rects;
        rwso.visibility_rects = (struct rail_window_rect *)g_malloc(bytes, 0);

        for (index = 0; index < rwso.num_visibility_rects; index++)
        {
            in_uint16_le(s, rwso.visibility_rects[index].left);
            in_uint16_le(s, rwso.visibility_rects[index].top);
            in_uint16_le(s, rwso.visibility_rects[index].right);
            in_uint16_le(s, rwso.visibility_rects[index].bottom);
        }
    }

    in_uint32_le(s, flags);
    mod->server_window_new_update(mod, window_id, &rwso, flags);
    rv = 0;
    g_free(rwso.title_info);
    g_free(rwso.window_rects);
    g_free(rwso.visibility_rects);
    return rv;
}

/******************************************************************************/
/* return error */
static int APP_CC
process_server_window_delete(struct mod *mod, struct stream *s)
{
    int window_id;
    int rv;

    in_uint32_le(s, window_id);
    mod->server_window_delete(mod, window_id);
    rv = 0;
    return rv;
}

/******************************************************************************/
/* return error */
static int APP_CC
process_server_window_show(struct mod* mod, struct stream* s)
{
    int window_id;
    int rv;
    int flags;
    struct rail_window_state_order rwso;

    g_memset(&rwso, 0, sizeof(rwso));
    in_uint32_le(s, window_id);
    in_uint32_le(s, flags);
    in_uint32_le(s, rwso.show_state);
    mod->server_window_new_update(mod, window_id, &rwso, flags);
    rv = 0;
    return rv;
}

/******************************************************************************/
/* return error */
static int APP_CC
process_server_add_char(struct mod *mod, struct stream *s)
{
    int rv;
    int font;
    int charactor;
    int x;
    int y;
    int cx;
    int cy;
    int len_bmpdata;
    char *bmpdata;

    in_uint16_le(s, font);
    in_uint16_le(s, charactor);
    in_sint16_le(s, x);
    in_sint16_le(s, y);
    in_uint16_le(s, cx);
    in_uint16_le(s, cy);
    in_uint16_le(s, len_bmpdata);
    in_uint8p(s, bmpdata, len_bmpdata);
    rv = mod->server_add_char(mod, font, charactor, x, y, cx, cy, bmpdata);
    return rv;
}


/******************************************************************************/
/* return error */
static int APP_CC
process_server_add_char_alpha(struct mod *mod, struct stream *s)
{
    int rv;
    int font;
    int charactor;
    int x;
    int y;
    int cx;
    int cy;
    int len_bmpdata;
    char *bmpdata;

    in_uint16_le(s, font);
    in_uint16_le(s, charactor);
    in_sint16_le(s, x);
    in_sint16_le(s, y);
    in_uint16_le(s, cx);
    in_uint16_le(s, cy);
    in_uint16_le(s, len_bmpdata);
    in_uint8p(s, bmpdata, len_bmpdata);
    rv = mod->server_add_char_alpha(mod, font, charactor, x, y, cx, cy,
                                    bmpdata);
    return rv;
}

/******************************************************************************/
/* return error */
static int APP_CC
process_server_draw_text(struct mod *mod, struct stream *s)
{
    int rv;
    int font;
    int flags;
    int mixmode;
    int clip_left;
    int clip_top;
    int clip_right;
    int clip_bottom;
    int box_left;
    int box_top;
    int box_right;
    int box_bottom;
    int x;
    int y;
    int len_bmpdata;
    char *bmpdata;

    in_uint16_le(s, font);
    in_uint16_le(s, flags);
    in_uint16_le(s, mixmode);
    in_sint16_le(s, clip_left);
    in_sint16_le(s, clip_top);
    in_sint16_le(s, clip_right);
    in_sint16_le(s, clip_bottom);
    in_sint16_le(s, box_left);
    in_sint16_le(s, box_top);
    in_sint16_le(s, box_right);
    in_sint16_le(s, box_bottom);
    in_sint16_le(s, x);
    in_sint16_le(s, y);
    in_uint16_le(s, len_bmpdata);
    in_uint8p(s, bmpdata, len_bmpdata);
    rv = mod->server_draw_text(mod, font, flags, mixmode, clip_left, clip_top,
                               clip_right, clip_bottom, box_left, box_top,
                               box_right, box_bottom, x, y, bmpdata, len_bmpdata);
    return rv;
}

/******************************************************************************/
/* return error */
static int APP_CC
process_server_create_os_surface_bpp(struct mod *mod, struct stream *s)
{
    int rv;
    int rdpid;
    int width;
    int height;
    int bpp;

    in_uint32_le(s, rdpid);
    in_uint16_le(s, width);
    in_uint16_le(s, height);
    in_uint8(s, bpp);
    rv = mod->server_create_os_surface_bpp(mod, rdpid, width, height, bpp);
    return rv;
}


/******************************************************************************/
/* return error */
static int APP_CC
process_server_paint_rect_bpp(struct mod *mod, struct stream *s)
{
    int rv;
    int x;
    int y;
    int cx;
    int cy;
    int len_bmpdata;
    char *bmpdata;
    int width;
    int height;
    int srcx;
    int srcy;
    int bpp;

    in_sint16_le(s, x);
    in_sint16_le(s, y);
    in_uint16_le(s, cx);
    in_uint16_le(s, cy);
    in_uint32_le(s, len_bmpdata);
    in_uint8p(s, bmpdata, len_bmpdata);
    in_uint16_le(s, width);
    in_uint16_le(s, height);
    in_sint16_le(s, srcx);
    in_sint16_le(s, srcy);
    in_uint8(s, bpp);
    rv = mod->server_paint_rect_bpp(mod, x, y, cx, cy,
                                    bmpdata, width, height,
                                    srcx, srcy, bpp);
    return rv;
}

/******************************************************************************/
/* return error */
static int APP_CC
process_server_composite(struct mod *mod, struct stream *s)
{
    int rv;
    int srcidx;
    int srcformat;
    int srcwidth;
    int srcrepeat;
    int transform[10];
    int mskflags;
    int mskidx;
    int mskformat;
    int mskwidth;
    int mskrepeat;
    int op;
    int srcx;
    int srcy;
    int mskx;
    int msky;
    int dstx;
    int dsty;
    int width;
    int height;
    int dstformat;

    in_uint16_le(s, srcidx);
    in_uint32_le(s, srcformat);
    in_uint16_le(s, srcwidth);
    in_uint8(s, srcrepeat);
    g_memcpy(transform, s->p, 40);
    in_uint8s(s, 40);
    in_uint8(s, mskflags);
    in_uint16_le(s, mskidx);
    in_uint32_le(s, mskformat);
    in_uint16_le(s, mskwidth);
    in_uint8(s, mskrepeat);
    in_uint8(s, op);
    in_sint16_le(s, srcx);
    in_sint16_le(s, srcy);
    in_sint16_le(s, mskx);
    in_sint16_le(s, msky);
    in_sint16_le(s, dstx);
    in_sint16_le(s, dsty);
    in_uint16_le(s, width);
    in_uint16_le(s, height);
    in_uint32_le(s, dstformat);
    rv = mod->server_composite(mod, srcidx, srcformat, srcwidth, srcrepeat,
                               transform, mskflags, mskidx, mskformat,
                               mskwidth, mskrepeat, op, srcx, srcy, mskx, msky,
                               dstx, dsty, width, height, dstformat);
    return rv;
}

/******************************************************************************/
/* return error */
static int APP_CC
process_server_set_pointer_ex(struct mod *mod, struct stream *s)
{
    int rv;
    int x;
    int y;
    int bpp;
    int Bpp;
    char cur_data[32 * (32 * 4)];
    char cur_mask[32 * (32 / 8)];

    in_sint16_le(s, x);
    in_sint16_le(s, y);
    in_uint16_le(s, bpp);
    Bpp = (bpp == 0) ? 3 : (bpp + 7) / 8;
    in_uint8a(s, cur_data, 32 * (32 * Bpp));
    in_uint8a(s, cur_mask, 32 * (32 / 8));
    rv = mod->server_set_cursor_ex(mod, x, y, cur_data, cur_mask, bpp);
    return rv;
}

/******************************************************************************/
/* return error */
static int APP_CC
send_paint_rect_ack(struct mod *mod, int flags, int x, int y, int cx, int cy,
                    int frame_id)
{
    int len;
    struct stream *s;

    make_stream(s);
    init_stream(s, 8192);
    s_push_layer(s, iso_hdr, 4);
    out_uint16_le(s, 105);
    out_uint32_le(s, flags);
    out_uint32_le(s, frame_id);
    out_uint32_le(s, x);
    out_uint32_le(s, y);
    out_uint32_le(s, cx);
    out_uint32_le(s, cy);
    s_mark_end(s);
    len = (int)(s->end - s->data);
    s_pop_layer(s, iso_hdr);
    out_uint32_le(s, len);
    lib_send(mod, s->data, len);
    free_stream(s);
    return 0;
}

/******************************************************************************/
/* return error */
static int APP_CC
process_server_paint_rect_shmem(struct mod *mod, struct stream *s)
{
    int rv;
    int x;
    int y;
    int cx;
    int cy;
    int flags;
    int frame_id;
    int shmem_id;
    int shmem_offset;
    int width;
    int height;
    int srcx;
    int srcy;
    char *bmpdata;

    in_sint16_le(s, x);
    in_sint16_le(s, y);
    in_uint16_le(s, cx);
    in_uint16_le(s, cy);
    in_uint32_le(s, flags);
    in_uint32_le(s, frame_id);
    in_uint32_le(s, shmem_id);
    in_uint32_le(s, shmem_offset);
    in_uint16_le(s, width);
    in_uint16_le(s, height);
    in_sint16_le(s, srcx);
    in_sint16_le(s, srcy);
    bmpdata = 0;
    if (flags == 0) /* screen */
    {
        if (mod->screen_shmem_id == 0)
        {
            mod->screen_shmem_id = shmem_id;
            mod->screen_shmem_pixels = g_shmat(mod->screen_shmem_id);
        }
        if (mod->screen_shmem_pixels != 0)
        {
            bmpdata = mod->screen_shmem_pixels + shmem_offset;
        }
    }
    if (bmpdata != 0)
    {
        rv = mod->server_paint_rect(mod, x, y, cx, cy,
                                    bmpdata, width, height,
                                    srcx, srcy);
    }
    else
    {
        rv = 1;
    }
    send_paint_rect_ack(mod, flags, x, y, cx, cy, frame_id);
    return rv;
}

/******************************************************************************/
/* return error */
static int APP_CC
send_paint_rect_ex_ack(struct mod *mod, int flags, int frame_id)
{
    int len;
    struct stream *s;

    make_stream(s);
    init_stream(s, 8192);
    s_push_layer(s, iso_hdr, 4);
    out_uint16_le(s, 106);
    out_uint32_le(s, flags);
    out_uint32_le(s, frame_id);
    s_mark_end(s);
    len = (int)(s->end - s->data);
    s_pop_layer(s, iso_hdr);
    out_uint32_le(s, len);
    lib_send(mod, s->data, len);
    free_stream(s);
    return 0;
}

/******************************************************************************/
/* return error */
static int APP_CC
process_server_paint_rect_shmem_ex(struct mod *amod, struct stream *s)
{
    int num_drects;
    int num_crects;
    int flags;
    int frame_id;
    int shmem_id;
    int shmem_offset;
    int width;
    int height;
    int x;
    int y;
    int cx;
    int cy;
    int index;
    int rv;
    tsi16 *ldrects;
    tsi16 *ldrects1;
    tsi16 *lcrects;
    tsi16 *lcrects1;
    char *bmpdata;

    /* dirty pixels */
    in_uint16_le(s, num_drects);
    ldrects = (tsi16 *) g_malloc(2 * 4 * num_drects, 0);
    ldrects1 = ldrects;
    for (index = 0; index < num_drects; index++)
    {
        in_sint16_le(s, ldrects1[0]);
        in_sint16_le(s, ldrects1[1]);
        in_sint16_le(s, ldrects1[2]);
        in_sint16_le(s, ldrects1[3]);
        ldrects1 += 4;
    }

    /* copied pixels */
    in_uint16_le(s, num_crects);
    lcrects = (tsi16 *) g_malloc(2 * 4 * num_crects, 0);
    lcrects1 = lcrects;
    for (index = 0; index < num_crects; index++)
    {
        in_sint16_le(s, lcrects1[0]);
        in_sint16_le(s, lcrects1[1]);
        in_sint16_le(s, lcrects1[2]);
        in_sint16_le(s, lcrects1[3]);
        lcrects1 += 4;
    }

    in_uint32_le(s, flags);
    in_uint32_le(s, frame_id);
    in_uint32_le(s, shmem_id);
    in_uint32_le(s, shmem_offset);

    in_uint16_le(s, width);
    in_uint16_le(s, height);

    bmpdata = 0;
    if (flags == 0) /* screen */
    {
        if (amod->screen_shmem_id == 0)
        {
            amod->screen_shmem_id = shmem_id;
            amod->screen_shmem_pixels = g_shmat(amod->screen_shmem_id);
        }
        if (amod->screen_shmem_pixels != 0)
        {
            bmpdata = amod->screen_shmem_pixels + shmem_offset;
        }
    }
    if (bmpdata != 0)
    {

        rv = amod->server_paint_rects(amod, num_drects, ldrects,
                                      num_crects, lcrects,
                                      bmpdata, width, height, 0);
    }
    else
    {
        rv = 1;
    }

    send_paint_rect_ex_ack(amod, flags, frame_id);

    g_free(lcrects);
    g_free(ldrects);

    return 0;
}

/******************************************************************************/
/* return error */
static int APP_CC
lib_mod_process_orders(struct mod *mod, int type, struct stream *s)
{
    int rv;

    rv = 0;
    switch (type)
    {
        case 1: /* server_begin_update */
            rv = mod->server_begin_update(mod);
            break;
        case 2: /* server_end_update */
            rv = mod->server_end_update(mod);
            break;
        case 3: /* server_fill_rect */
            rv = process_server_fill_rect(mod, s);
            break;
        case 4: /* server_screen_blt */
            rv = process_server_screen_blt(mod, s);
            break;
        case 5: /* server_paint_rect */
            rv = process_server_paint_rect(mod, s);
            break;
        case 10: /* server_set_clip */
            rv = process_server_set_clip(mod, s);
            break;
        case 11: /* server_reset_clip */
            rv = process_server_reset_clip(mod, s);
            break;
        case 12: /* server_set_fgcolor */
            rv = process_server_set_fgcolor(mod, s);
            break;
        case 13: /* server_set_bgcolor */
            rv = process_server_set_bgcolor(mod, s);
            break;
        case 14: /* server_set_opcode */
            rv =  process_server_set_opcode(mod, s);
            break;
        case 17: /* server_set_pen */
            rv = process_server_set_pen(mod, s);
            break;
        case 18: /* server_draw_line */
            rv = process_server_draw_line(mod, s);
            break;
        case 19: /* server_set_cursor */
            rv = process_server_set_cursor(mod, s);
            break;
        case 20: /* server_create_os_surface */
            rv = process_server_create_os_surface(mod, s);
            break;
        case 21: /* server_switch_os_surface */
            rv = process_server_switch_os_surface(mod, s);
            break;
        case 22: /* server_delete_os_surface */
            rv = process_server_delete_os_surface(mod, s);
            break;
        case 23: /* server_paint_rect_os */
            rv = process_server_paint_rect_os(mod, s);
            break;
        case 24: /* server_set_hints */
            rv = process_server_set_hints(mod, s);
            break;
        case 25: /* server_window_new_update */
            rv = process_server_window_new_update(mod, s);
            break;
        case 26: /* server_window_delete */
            rv = process_server_window_delete(mod, s);
            break;
        case 27: /* server_window_new_update - show */
            rv = process_server_window_show(mod, s);
            break;
        case 28: /* server_add_char */
            rv = process_server_add_char(mod, s);
            break;
        case 29: /* server_add_char_alpha */
            rv = process_server_add_char_alpha(mod, s);
            break;
        case 30: /* server_draw_text */
            rv = process_server_draw_text(mod, s);
            break;
        case 31: /* server_create_os_surface_bpp */
            rv = process_server_create_os_surface_bpp(mod, s);
            break;
        case 32: /* server_paint_rect_bpp */
            rv = process_server_paint_rect_bpp(mod, s);
            break;
        case 33: /* server_composite */
            rv = process_server_composite(mod, s);
            break;
        case 51: /* server_set_pointer_ex */
            rv = process_server_set_pointer_ex(mod, s);
            break;
        case 60: /* server_paint_rect_shmem */
            rv = process_server_paint_rect_shmem(mod, s);
            break;
        case 61: /* server_paint_rect_shmem_ex */
            rv = process_server_paint_rect_shmem_ex(mod, s);
            break;
        default:
            g_writeln("lib_mod_process_orders: unknown order type %d", type);
            rv = 0;
            break;
    }
    return rv;
}

/******************************************************************************/
/* return error */
static int APP_CC
lib_send_client_info(struct mod *mod)
{
    struct stream *s;
    int len;

    make_stream(s);
    init_stream(s, 8192);
    s_push_layer(s, iso_hdr, 4);
    out_uint16_le(s, 104);
    g_memcpy(s->p, &(mod->client_info), sizeof(mod->client_info));
    s->p += sizeof(mod->client_info);
    s_mark_end(s);
    len = (int)(s->end - s->data);
    s_pop_layer(s, iso_hdr);
    out_uint32_le(s, len);
    lib_send(mod, s->data, len);
    free_stream(s);
    return 0;
}

/******************************************************************************/
/* return error */
int DEFAULT_CC
lib_mod_signal(struct mod *mod)
{
    struct stream *s;
    int num_orders;
    int index;
    int rv;
    int len;
    int type;
    char *phold;

    LIB_DEBUG(mod, "in lib_mod_signal");
    make_stream(s);
    init_stream(s, 8192);
    rv = lib_recv(mod, s->data, 8);

    if (rv == 0)
    {
        in_uint16_le(s, type);
        in_uint16_le(s, num_orders);
        in_uint32_le(s, len);

        if (type == 1) /* original order list */
        {
            init_stream(s, len);
            rv = lib_recv(mod, s->data, len);

            if (rv == 0)
            {
                for (index = 0; index < num_orders; index++)
                {
                    in_uint16_le(s, type);
                    rv = lib_mod_process_orders(mod, type, s);

                    if (rv != 0)
                    {
                        break;
                    }
                }
            }
        }
        else if (type == 2) /* caps */
        {
            g_writeln("lib_mod_signal: type 2 len %d", len);
            init_stream(s, len);
            rv = lib_recv(mod, s->data, len);

            if (rv == 0)
            {
                for (index = 0; index < num_orders; index++)
                {
                    phold = s->p;
                    in_uint16_le(s, type);
                    in_uint16_le(s, len);

                    switch (type)
                    {
                        default:
                            g_writeln("lib_mod_signal: unknown cap type %d len %d",
                                      type, len);
                            break;
                    }

                    s->p = phold + len;
                }

                lib_send_client_info(mod);
            }
        }
        else if (type == 3) /* order list with len after type */
        {
            init_stream(s, len);
            rv = lib_recv(mod, s->data, len);

            if (rv == 0)
            {
                for (index = 0; index < num_orders; index++)
                {
                    phold = s->p;
                    in_uint16_le(s, type);
                    in_uint16_le(s, len);
                    rv = lib_mod_process_orders(mod, type, s);

                    if (rv != 0)
                    {
                        break;
                    }

                    s->p = phold + len;
                }
            }
        }
        else
        {
            g_writeln("unknown type %d", type);
        }
    }

    free_stream(s);
    LIB_DEBUG(mod, "out lib_mod_signal");
    return rv;
}

/******************************************************************************/
/* return error */
int DEFAULT_CC
lib_mod_end(struct mod *mod)
{
    if (mod->screen_shmem_pixels != 0)
    {
        g_shmdt(mod->screen_shmem_pixels);
        mod->screen_shmem_pixels = 0;
    }
    return 0;
}

/******************************************************************************/
/* return error */
int DEFAULT_CC
lib_mod_set_param(struct mod *mod, char *name, char *value)
{
    if (g_strcasecmp(name, "username") == 0)
    {
        g_strncpy(mod->username, value, 255);
    }
    else if (g_strcasecmp(name, "password") == 0)
    {
        g_strncpy(mod->password, value, 255);
    }
    else if (g_strcasecmp(name, "ip") == 0)
    {
        g_strncpy(mod->ip, value, 255);
    }
    else if (g_strcasecmp(name, "port") == 0)
    {
        g_strncpy(mod->port, value, 255);
    }
    else if (g_strcasecmp(name, "client_info") == 0)
    {
        g_memcpy(&(mod->client_info), value, sizeof(mod->client_info));
    }

    return 0;
}

/******************************************************************************/
/* return error */
int DEFAULT_CC
lib_mod_get_wait_objs(struct mod *mod, tbus *read_objs, int *rcount,
                      tbus *write_objs, int *wcount, int *timeout)
{
    int i;

    i = *rcount;

    if (mod != 0)
    {
        if (mod->sck_obj != 0)
        {
            read_objs[i++] = mod->sck_obj;
        }
    }

    *rcount = i;
    return 0;
}

/******************************************************************************/
/* return error */
int DEFAULT_CC
lib_mod_check_wait_objs(struct mod *mod)
{
    int rv;

    rv = 0;

    if (mod != 0)
    {
        if (mod->sck_obj != 0)
        {
            if (g_is_wait_obj_set(mod->sck_obj))
            {
                rv = lib_mod_signal(mod);
            }
        }
    }

    return rv;
}

/******************************************************************************/
struct mod *EXPORT_CC
mod_init(void)
{
    struct mod *mod;

    mod = (struct mod *)g_malloc(sizeof(struct mod), 1);
    mod->size = sizeof(struct mod);
    mod->version = CURRENT_MOD_VER;
    mod->handle = (tbus)mod;
    mod->mod_connect = lib_mod_connect;
    mod->mod_start = lib_mod_start;
    mod->mod_event = lib_mod_event;
    mod->mod_signal = lib_mod_signal;
    mod->mod_end = lib_mod_end;
    mod->mod_set_param = lib_mod_set_param;
    mod->mod_get_wait_objs = lib_mod_get_wait_objs;
    mod->mod_check_wait_objs = lib_mod_check_wait_objs;
    return mod;
}

/******************************************************************************/
int EXPORT_CC
mod_exit(struct mod *mod)
{
    if (mod == 0)
    {
        return 0;
    }

    g_delete_wait_obj_from_socket(mod->sck_obj);
    g_tcp_close(mod->sck);
    g_free(mod);
    return 0;
}
