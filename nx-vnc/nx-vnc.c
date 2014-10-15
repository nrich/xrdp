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
 * libvnc
 */

#include "nx-vnc.h"
#include "log.h"

#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <signal.h>

#define NX_SSH_TYPE_DSS 1
#define NX_SSH_TYPE_RSA 2

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


static void session_send_command(struct nxvnc *v, const char *cmd) {
    ssh_session session = v->session;
    ssh_channel channel = v->channel;

    channel_write(channel, cmd, g_strlen(cmd));

    ssh_set_fd_towrite(session);
    channel_write(channel, "\n", 1);
}

static int get_response(struct nxvnc *v, int timeout_in_seconds, char *output) {
    int rc;
    char buffer[256];
    int nbytes;
    int totalbytes;

    if (ssh_channel_is_open(v->channel) && !ssh_channel_is_eof(v->channel)) {
        nbytes = ssh_channel_read_nonblocking(v->channel, buffer, sizeof(buffer), 0);
        if (nbytes < 0) {
            return 0;
        }

        if (nbytes > 0) {
            strncat(output, buffer, nbytes);
            totalbytes += nbytes;
        }

        if (nbytes == 0) {
        }
    }

    return totalbytes > 0;
}

static int get_expected_response(struct nxvnc *v, int expected_code) {
    char output[1024];
    int response_code = -1;
    char *curLine;
    int count = 2;

    output[0] = '\0';
    while (count--) {
        get_response(v, 1, output);
	v->server_msg(v, "Looped in get_expected_response", 1);
        usleep(500000);
    }

    v->server_msg(v, "Done loop", 1);
    v->server_msg(v, output, 1);

    curLine = output;
    while (curLine) {
        char *nextLine = g_strchr(curLine, '\n');

        if (sscanf(curLine, "NX> %i ", &response_code) > 0) {
	    if (response_code == expected_code)
                break;
        } 

        if (nextLine)
            *nextLine = '\0';

        curLine = nextLine ? (nextLine + 1) : NULL;
    }

    return response_code == expected_code;
}

static int get_session(struct nxvnc *v, char *ip) {
    char output[10240];
    int response_code = -1;
    char *curLine;
    int count = 10;

    output[0] = '\0';
    while (count--) {
        get_response(v, 1, output);
	usleep(500000);
    }

    v->server_msg(v, "Done loop", 1);
    v->server_msg(v, output, 1);

    curLine = output;
    while (curLine) {
        char *nextLine = g_strchr(curLine, '\n');
        int display;
        char username[64];
        char sessiontoken[33];

        if (sscanf(curLine, "NX> %i ", &response_code) > 0) {
	    if (response_code == 105) 
                break;
        } 

        if (nextLine)
            *nextLine = '\0';

        if (sscanf(curLine, "%d %s %s %s", &display, username, ip, sessiontoken) > 0) {
            //v->server_msg(v, "Found session name %s", sessiontoken);
            v->server_msg(v, "Found session name", 1);
            v->server_msg(v, sessiontoken, 1);

            v->display = display;
            v->sessiontoken = g_strdup(sessiontoken);
            break;
        }

        curLine = nextLine ? (nextLine + 1) : NULL;
    }

    v->server_msg(v, "Finished session list", 0);
    //return response_code == 105;
    return v->sessiontoken ? 1 : 0;
}

int get_session_info(struct nxvnc *v) {
    char output[10240];
    int response_code = -1;
    char *curLine;
    int count = 10;

    output[0] = '\0';
    while (count--) {
        get_response(v, 1, output);
        usleep(500000);
    }

    v->server_msg(v, "Done loop", 1);
    v->server_msg(v, output, 1);

    curLine = output;
    while (curLine) {
        char cookie[33];
        char sessionid[128];

        char *nextLine = g_strchr(curLine, '\n');
        int status;

        if (nextLine)
            *nextLine = '\0';

        if (sscanf(curLine, "NX> %i ", &status) > 0) {
            if (status == 700) {
                if (sscanf(curLine, "NX> 700 Session id: %s", sessionid) > 0) {
                    //v->server_msg(v, "Found session ID %s", sessionid);
                    v->sessionid = g_strdup(sessionid);
                }
            } else if (status == 701) {
                if (sscanf(curLine, "NX> 701 Proxy cookie: %32s", cookie) > 0) {
                    //v->server_msg(v, "Found session cookie %s", cookie);
                    v->cookie = g_strdup(cookie);
                }
            } else if (status == 105) {
                response_code = status;
            }
        }

        if (nextLine)
            *nextLine = '\n';

        curLine = nextLine ? (nextLine + 1) : NULL;
    }

    return response_code == 105;
}

static int get_expected_response_long(struct nxvnc *v, int expected_code) {
    char output[1024];
    int response_code = -1;
    char *curLine;
    int count = 10;

    output[0] = '\0';
    while (count--) {
        get_response(v, 1, output);
	v->server_msg(v, "Looped in get_expected_response", 1);
        usleep(500000);
    }

    v->server_msg(v, "Done loop", 1);
    v->server_msg(v, output, 1);

    curLine = output;
    while (curLine) {
        char *nextLine = g_strchr(curLine, '\n');

        if (sscanf(curLine, "NX> %i ", &response_code) > 0) {
	    if (response_code == expected_code)
                break;
        } 

        if (nextLine)
            *nextLine = '\0';

        curLine = nextLine ? (nextLine + 1) : NULL;
    }

    return response_code == expected_code;
}


/******************************************************************************/
/* taken from vncauth.c */
void DEFAULT_CC
rfbEncryptBytes(char *bytes, char *passwd)
{
    char key[12];

    /* key is simply password padded with nulls */
    g_memset(key, 0, sizeof(key));
    g_strncpy(key, passwd, 8);
    rfbDesKey((unsigned char *)key, EN0); /* 0, encrypt */
    rfbDes((unsigned char *)bytes, (unsigned char *)bytes);
    rfbDes((unsigned char *)(bytes + 8), (unsigned char *)(bytes + 8));
}

/******************************************************************************/
/* returns error */
int DEFAULT_CC
lib_recv(struct nxvnc *v, char *data, int len)
{
    int rcvd;

    if (v->sck_closed)
    {
        return 1;
    }

    while (len > 0)
    {
        rcvd = g_tcp_recv(v->sck, data, len, 0);

        if (rcvd == -1)
        {
            if (g_tcp_last_error_would_block(v->sck))
            {
                if (v->server_is_term(v))
                {
                    return 1;
                }

                g_tcp_can_recv(v->sck, 10);
            }
            else
            {
                log_message(LOG_LEVEL_DEBUG, "VNC lib_recv return 1");
                return 1;
            }
        }
        else if (rcvd == 0)
        {
            v->sck_closed = 1;
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
lib_send(struct nxvnc *v, char *data, int len)
{
    int sent;

    if (v->sck_closed)
    {
        return 1;
    }

    while (len > 0)
    {
        sent = g_tcp_send(v->sck, data, len, 0);

        if (sent == -1)
        {
            if (g_tcp_last_error_would_block(v->sck))
            {
                if (v->server_is_term(v))
                {
                    return 1;
                }

                g_tcp_can_send(v->sck, 10);
            }
            else
            {
                return 1;
            }
        }
        else if (sent == 0)
        {
            v->sck_closed = 1;
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
static int DEFAULT_CC
lib_process_channel_data(struct nxvnc *v, int chanid, int flags, int size,
                         struct stream *s, int total_size)
{
    int type;
    int status;
    int length;
    int index;
    int format;
    struct stream *out_s;

    if (chanid == v->clip_chanid)
    {
        in_uint16_le(s, type);
        in_uint16_le(s, status);
        in_uint32_le(s, length);

        //g_writeln("clip data type %d status %d length %d", type, status, length);
        //g_hexdump(s->p, s->end - s->p);
        switch (type)
        {
            case 2: /* CLIPRDR_FORMAT_ANNOUNCE */
                make_stream(out_s);
                init_stream(out_s, 8192);
                out_uint16_le(out_s, 3);
                out_uint16_le(out_s, 1);
                out_uint32_le(out_s, 0);
                out_uint8s(out_s, 4); /* pad */
                s_mark_end(out_s);
                length = (int)(out_s->end - out_s->data);
                v->server_send_to_channel(v, v->clip_chanid, out_s->data, length, length, 3);
                free_stream(out_s);
                break;
            case 3: /* CLIPRDR_FORMAT_ACK */
                break;
            case 4: /* CLIPRDR_DATA_REQUEST */
                format = 0;

                if (length >= 4)
                {
                    in_uint32_le(s, format);
                }

                /* only support CF_TEXT and CF_UNICODETEXT */
                if ((format != 1) && (format != 13))
                {
                    break;
                }

                make_stream(out_s);
                init_stream(out_s, 8192);
                out_uint16_le(out_s, 5);
                out_uint16_le(out_s, 1);

                if (format == 13) /* CF_UNICODETEXT */
                {
                    out_uint32_le(out_s, v->clip_data_size * 2 + 2);

                    for (index = 0; index < v->clip_data_size; index++)
                    {
                        out_uint8(out_s, v->clip_data[index]);
                        out_uint8(out_s, 0);
                    }

                    out_uint8s(out_s, 2);
                }
                else if (format == 1) /* CF_TEXT */
                {
                    out_uint32_le(out_s, v->clip_data_size + 1);

                    for (index = 0; index < v->clip_data_size; index++)
                    {
                        out_uint8(out_s, v->clip_data[index]);
                    }

                    out_uint8s(out_s, 1);
                }

                out_uint8s(out_s, 4); /* pad */
                s_mark_end(out_s);
                length = (int)(out_s->end - out_s->data);
                v->server_send_to_channel(v, v->clip_chanid, out_s->data, length,
                                          length, 3);
                free_stream(out_s);
                break;
            default:
            {
                log_message(LOG_LEVEL_DEBUG, "VNC clip information unhandled");
                break;
            }
        }
    }
    else
    {
        log_message(LOG_LEVEL_DEBUG, "lib_process_channel_data: unknown chanid:",
                    "%d :(v->clip_chanid) %d", chanid, v->clip_chanid);
    }

    return 0;
}

/******************************************************************************/
int DEFAULT_CC
lib_mod_event(struct nxvnc *v, int msg, long param1, long param2,
              long param3, long param4)
{
    struct stream *s;
    int key;
    int error;
    int x;
    int y;
    int cx;
    int cy;
    int size;
    int total_size;
    int chanid;
    int flags;
    char *data;
    char text[256];

    error = 0;
    make_stream(s);

    if (msg == 0x5555) /* channel data */
    {
        chanid = LOWORD(param1);
        flags = HIWORD(param1);
        size = (int)param2;
        data = (char *)param3;
        total_size = (int)param4;

        if ((size >= 0) && (size <= (32 * 1024)) && (data != 0))
        {
            init_stream(s, size);
            out_uint8a(s, data, size);
            s_mark_end(s);
            s->p = s->data;
            error = lib_process_channel_data(v, chanid, flags, size, s, total_size);
        }
        else
        {
            error = 1;
        }
    }
    else if ((msg >= 15) && (msg <= 16)) /* key events */
    {
        key = param2;

        if (key > 0)
        {
            if (key == 65027) /* altgr */
            {
                if (v->shift_state)
                {
                    /* fix for mstsc sending left control down with altgr */
                    init_stream(s, 8192);
                    out_uint8(s, 4);
                    out_uint8(s, 0); /* down flag */
                    out_uint8s(s, 2);
                    out_uint32_be(s, 65507); /* left control */
                    lib_send(v, s->data, 8);
                }
            }

            init_stream(s, 8192);
            out_uint8(s, 4);
            out_uint8(s, msg == 15); /* down flag */
            out_uint8s(s, 2);
            out_uint32_be(s, key);
            error = lib_send(v, s->data, 8);

            if (key == 65507) /* left control */
            {
                v->shift_state = msg == 15;
            }
        }
    }
    else if (msg >= 100 && msg <= 110) /* mouse events */
    {
        switch (msg)
        {
            case 100:
                break; /* WM_MOUSEMOVE */
            case 101:
                v->mod_mouse_state &= ~1;
                break; /* WM_LBUTTONUP */
            case 102:
                v->mod_mouse_state |= 1;
                break; /* WM_LBUTTONDOWN */
            case 103:
                v->mod_mouse_state &= ~4;
                break; /* WM_RBUTTONUP */
            case 104:
                v->mod_mouse_state |= 4;
                break; /* WM_RBUTTONDOWN */
            case 105:
                v->mod_mouse_state &= ~2;
                break;
            case 106:
                v->mod_mouse_state |= 2;
                break;
            case 107:
                v->mod_mouse_state &= ~8;
                break;
            case 108:
                v->mod_mouse_state |= 8;
                break;
            case 109:
                v->mod_mouse_state &= ~16;
                break;
            case 110:
                v->mod_mouse_state |= 16;
                break;
        }

        init_stream(s, 8192);
        out_uint8(s, 5);
        out_uint8(s, v->mod_mouse_state);
        out_uint16_be(s, param1);
        out_uint16_be(s, param2);
        error = lib_send(v, s->data, 6);
    }
    else if (msg == 200) /* invalidate */
    {
        /* FrambufferUpdateRequest */
        init_stream(s, 8192);
        out_uint8(s, 3);
        out_uint8(s, 0);
        x = (param1 >> 16) & 0xffff;
        out_uint16_be(s, x);
        y = param1 & 0xffff;
        out_uint16_be(s, y);
        cx = (param2 >> 16) & 0xffff;
        out_uint16_be(s, cx);
        cy = param2 & 0xffff;
        out_uint16_be(s, cy);
        error = lib_send(v, s->data, 10);
    }

    free_stream(s);
    return error;
}

//******************************************************************************
int DEFAULT_CC
get_pixel_safe(char *data, int x, int y, int width, int height, int bpp)
{
    int start = 0;
    int shift = 0;

    if (x < 0)
    {
        return 0;
    }

    if (y < 0)
    {
        return 0;
    }

    if (x >= width)
    {
        return 0;
    }

    if (y >= height)
    {
        return 0;
    }

    if (bpp == 1)
    {
        width = (width + 7) / 8;
        start = (y * width) + x / 8;
        shift = x % 8;
        return (data[start] & (0x80 >> shift)) != 0;
    }
    else if (bpp == 4)
    {
        width = (width + 1) / 2;
        start = y * width + x / 2;
        shift = x % 2;

        if (shift == 0)
        {
            return (data[start] & 0xf0) >> 4;
        }
        else
        {
            return data[start] & 0x0f;
        }
    }
    else if (bpp == 8)
    {
        return *(((unsigned char *)data) + (y * width + x));
    }
    else if (bpp == 15 || bpp == 16)
    {
        return *(((unsigned short *)data) + (y * width + x));
    }
    else if (bpp == 24 || bpp == 32)
    {
        return *(((unsigned int *)data) + (y * width + x));
    }
    else
    {
        log_message(LOG_LEVEL_ERROR, "error in get_pixel_safe bpp %d", bpp);
    }

    return 0;
}

/******************************************************************************/
void DEFAULT_CC
set_pixel_safe(char *data, int x, int y, int width, int height, int bpp,
               int pixel)
{
    int start = 0;
    int shift = 0;

    if (x < 0)
    {
        return;
    }

    if (y < 0)
    {
        return;
    }

    if (x >= width)
    {
        return;
    }

    if (y >= height)
    {
        return;
    }

    if (bpp == 1)
    {
        width = (width + 7) / 8;
        start = (y * width) + x / 8;
        shift = x % 8;

        if (pixel & 1)
        {
            data[start] = data[start] | (0x80 >> shift);
        }
        else
        {
            data[start] = data[start] & ~(0x80 >> shift);
        }
    }
    else if (bpp == 15 || bpp == 16)
    {
        *(((unsigned short *)data) + (y * width + x)) = pixel;
    }
    else if (bpp == 24)
    {
        *(data + (3 * (y * width + x)) + 0) = pixel >> 0;
        *(data + (3 * (y * width + x)) + 1) = pixel >> 8;
        *(data + (3 * (y * width + x)) + 2) = pixel >> 16;
    }
    else
    {
        log_message(LOG_LEVEL_ERROR, "error in set_pixel_safe bpp %d", bpp);
    }
}

/******************************************************************************/
int DEFAULT_CC
split_color(int pixel, int *r, int *g, int *b, int bpp, int *palette)
{
    if (bpp == 8)
    {
        if (pixel >= 0 && pixel < 256 && palette != 0)
        {
            *r = (palette[pixel] >> 16) & 0xff;
            *g = (palette[pixel] >> 8) & 0xff;
            *b = (palette[pixel] >> 0) & 0xff;
        }
    }
    else if (bpp == 15)
    {
        *r = ((pixel >> 7) & 0xf8) | ((pixel >> 12) & 0x7);
        *g = ((pixel >> 2) & 0xf8) | ((pixel >> 8) & 0x7);
        *b = ((pixel << 3) & 0xf8) | ((pixel >> 2) & 0x7);
    }
    else if (bpp == 16)
    {
        *r = ((pixel >> 8) & 0xf8) | ((pixel >> 13) & 0x7);
        *g = ((pixel >> 3) & 0xfc) | ((pixel >> 9) & 0x3);
        *b = ((pixel << 3) & 0xf8) | ((pixel >> 2) & 0x7);
    }
    else if (bpp == 24 || bpp == 32)
    {
        *r = (pixel >> 16) & 0xff;
        *g = (pixel >> 8) & 0xff;
        *b = pixel & 0xff;
    }
    else
    {
        log_message(LOG_LEVEL_ERROR, "error in split_color bpp %d", bpp);
    }

    return 0;
}

/******************************************************************************/
int DEFAULT_CC
make_color(int r, int g, int b, int bpp)
{
    if (bpp == 24)
    {
        return (r << 16) | (g << 8) | b;
    }
    else
    {
        log_message(LOG_LEVEL_ERROR, "error in make_color bpp %d", bpp);
    }

    return 0;
}

/******************************************************************************/
int DEFAULT_CC
lib_framebuffer_update(struct nxvnc *v)
{
    char *data;
    char *d1;
    char *d2;
    char cursor_data[32 * (32 * 3)];
    char cursor_mask[32 * (32 / 8)];
    char text[256];
    int num_recs;
    int i;
    int j;
    int k;
    int x;
    int y;
    int cx;
    int cy;
    int srcx;
    int srcy;
    int encoding;
    int Bpp;
    int pixel;
    int r;
    int g;
    int b;
    int data_size;
    int need_size;
    int error;
    struct stream *s;

    data_size = 0;
    data = 0;
    num_recs = 0;
    Bpp = (v->mod_bpp + 7) / 8;

    if (Bpp == 3)
    {
        Bpp = 4;
    }

    make_stream(s);
    init_stream(s, 8192);
    error = lib_recv(v, s->data, 3);

    if (error == 0)
    {
        in_uint8s(s, 1);
        in_uint16_be(s, num_recs);
        error = v->server_begin_update(v);
    }

    for (i = 0; i < num_recs; i++)
    {
        if (error != 0)
        {
            break;
        }

        init_stream(s, 8192);
        error = lib_recv(v, s->data, 12);

        if (error == 0)
        {
            in_uint16_be(s, x);
            in_uint16_be(s, y);
            in_uint16_be(s, cx);
            in_uint16_be(s, cy);
            in_uint32_be(s, encoding);

            if (encoding == 0) /* raw */
            {
                need_size = cx * cy * Bpp;

                if (need_size > data_size)
                {
                    g_free(data);
                    data = (char *)g_malloc(need_size, 0);
                    data_size = need_size;
                }

                error = lib_recv(v, data, need_size);

                if (error == 0)
                {
                    error = v->server_paint_rect(v, x, y, cx, cy, data, cx, cy, 0, 0);
                }
            }
            else if (encoding == 1) /* copy rect */
            {
                init_stream(s, 8192);
                error = lib_recv(v, s->data, 4);

                if (error == 0)
                {
                    in_uint16_be(s, srcx);
                    in_uint16_be(s, srcy);
                    error = v->server_screen_blt(v, x, y, cx, cy, srcx, srcy);
                }
            }
            else if (encoding == 0xffffff11) /* cursor */
            {
                g_memset(cursor_data, 0, 32 * (32 * 3));
                g_memset(cursor_mask, 0, 32 * (32 / 8));
                j = cx * cy * Bpp;
                k = ((cx + 7) / 8) * cy;
                init_stream(s, j + k);
                error = lib_recv(v, s->data, j + k);

                if (error == 0)
                {
                    in_uint8p(s, d1, j);
                    in_uint8p(s, d2, k);

                    for (j = 0; j < 32; j++)
                    {
                        for (k = 0; k < 32; k++)
                        {
                            pixel = get_pixel_safe(d2, k, 31 - j, cx, cy, 1);
                            set_pixel_safe(cursor_mask, k, j, 32, 32, 1, !pixel);

                            if (pixel)
                            {
                                pixel = get_pixel_safe(d1, k, 31 - j, cx, cy, v->mod_bpp);
                                split_color(pixel, &r, &g, &b, v->mod_bpp, v->palette);
                                pixel = make_color(r, g, b, 24);
                                set_pixel_safe(cursor_data, k, j, 32, 32, 24, pixel);
                            }
                        }
                    }

                    /* keep these in 32x32, vnc cursor can be alot bigger */
                    if (x > 31)
                    {
                        x = 31;
                    }

                    if (y > 31)
                    {
                        y = 31;
                    }

                    error = v->server_set_cursor(v, x, y, cursor_data, cursor_mask);
                }
            }
            else if (encoding == 0xffffff21) /* desktop size */
            {
                v->mod_width = cx;
                v->mod_height = cy;
                error = v->server_reset(v, cx, cy, v->mod_bpp);
            }
            else
            {
                g_sprintf(text, "VNC error in lib_framebuffer_update encoding = %8.8x",
                          encoding);
                v->server_msg(v, text, 1);
            }
        }
    }

    if (error == 0)
    {
        error = v->server_end_update(v);
    }

    g_free(data);

    if (error == 0)
    {
        /* FrambufferUpdateRequest */
        init_stream(s, 8192);
        out_uint8(s, 3);
        out_uint8(s, 1);
        out_uint16_be(s, 0);
        out_uint16_be(s, 0);
        out_uint16_be(s, v->mod_width);
        out_uint16_be(s, v->mod_height);
        error = lib_send(v, s->data, 10);
    }

    free_stream(s);
    return error;
}

/******************************************************************************/
int DEFAULT_CC
lib_clip_data(struct nxvnc *v)
{
    struct stream *s;
    struct stream *out_s;
    int size;
    int error;

    g_free(v->clip_data);
    v->clip_data = 0;
    v->clip_data_size = 0;
    make_stream(s);
    init_stream(s, 8192);
    error = lib_recv(v, s->data, 7);

    if (error == 0)
    {
        in_uint8s(s, 3);
        in_uint32_be(s, size);
        v->clip_data = (char *)g_malloc(size, 0);
        v->clip_data_size = size;
        error = lib_recv(v, v->clip_data, size);
    }

    if (error == 0)
    {
        make_stream(out_s);
        init_stream(out_s, 8192);
        out_uint16_le(out_s, 2);
        out_uint16_le(out_s, 0);
        out_uint32_le(out_s, 0x90);
        out_uint8(out_s, 0x0d);
        out_uint8s(out_s, 35);
        out_uint8(out_s, 0x10);
        out_uint8s(out_s, 35);
        out_uint8(out_s, 0x01);
        out_uint8s(out_s, 35);
        out_uint8(out_s, 0x07);
        out_uint8s(out_s, 35);
        out_uint8s(out_s, 4);
        s_mark_end(out_s);
        size = (int)(out_s->end - out_s->data);
        error = v->server_send_to_channel(v, v->clip_chanid, out_s->data, size, size, 3);
        free_stream(out_s);
    }

    free_stream(s);
    return error;
}

/******************************************************************************/
int DEFAULT_CC
lib_palette_update(struct nxvnc *v)
{
    struct stream *s;
    int first_color;
    int num_colors;
    int i;
    int r;
    int g;
    int b;
    int error;

    make_stream(s);
    init_stream(s, 8192);
    error = lib_recv(v, s->data, 5);

    if (error == 0)
    {
        in_uint8s(s, 1);
        in_uint16_be(s, first_color);
        in_uint16_be(s, num_colors);
        init_stream(s, 8192);
        error = lib_recv(v, s->data, num_colors * 6);
    }

    if (error == 0)
    {
        for (i = 0; i < num_colors; i++)
        {
            in_uint16_be(s, r);
            in_uint16_be(s, g);
            in_uint16_be(s, b);
            r = r >> 8;
            g = g >> 8;
            b = b >> 8;
            v->palette[first_color + i] = (r << 16) | (g << 8) | b;
        }

        error = v->server_begin_update(v);
    }

    if (error == 0)
    {
        error = v->server_palette(v, v->palette);
    }

    if (error == 0)
    {
        error = v->server_end_update(v);
    }

    free_stream(s);
    return error;
}

/******************************************************************************/
int DEFAULT_CC
lib_bell_trigger(struct nxvnc *v)
{
    struct stream *s;
    int error;

    error = v->server_bell_trigger(v);
    return error;
}

/******************************************************************************/
int DEFAULT_CC
lib_mod_signal(struct nxvnc *v)
{
    char type;
    int error;
    char text[256];

    error = lib_recv(v, &type, 1);

    if (error == 0)
    {
        if (type == 0) /* framebuffer update */
        {
            error = lib_framebuffer_update(v);
        }
        else if (type == 1) /* palette */
        {
            error = lib_palette_update(v);
        }
        else if (type == 2) /* bell */
        {
            error = lib_bell_trigger(v);
        }
        else if (type == 3) /* clipboard */
        {
            log_message(LOG_LEVEL_DEBUG, "VNC got clip data");
            error = lib_clip_data(v);
        }
        else
        {
            g_sprintf(text, "VNC unknown in lib_mod_signal %d", type);
            v->server_msg(v, text, 1);
        }
    }

    return error;
}

/******************************************************************************/
int DEFAULT_CC
lib_mod_start(struct nxvnc *v, int w, int h, int bpp)
{
    v->server_begin_update(v);
    v->server_set_fgcolor(v, 0);
    v->server_fill_rect(v, 0, 0, w, h);
    v->server_end_update(v);
    v->server_width = w;
    v->server_height = h;
    v->server_bpp = bpp;
    return 0;
}

/******************************************************************************/
static int APP_CC
lib_open_clip_channel(struct nxvnc *v)
{
    char init_data[12] = { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

    v->clip_chanid = v->server_get_channel_id(v, "cliprdr");

    if (v->clip_chanid >= 0)
    {
        v->server_send_to_channel(v, v->clip_chanid, init_data, 12, 12, 3);
    }

    return 0;
}

/******************************************************************************/
/*
  return error
*/
int DEFAULT_CC
lib_mod_connect(struct nxvnc *v)
{
    char cursor_data[32 * (32 * 3)];
    char cursor_mask[32 * (32 / 8)];
    char con_port[256];
    char text[256];
    struct stream *s;
    struct stream *pixel_format;
    int error;
    int i;
    int check_sec_result;

    int rc = 0;
    ssh_private_key privkey;
    ssh_public_key pubkey;
    ssh_string pubkeystr;
    unsigned int nbytes;
    char tmpfile[L_tmpnam + 1];
    char pidfile[128];
    char ip[16];

    v->server_msg(v, "NX started connecting", 0);

    v->session = ssh_new();
    if (v->session == NULL) {
        v->server_msg(v, "Failed to create SSH session", 1);
        return 1;
    }
        
    ssh_options_set(v->session, SSH_OPTIONS_HOST, "localhost");
    ssh_options_set(v->session, SSH_OPTIONS_USER, "nx");

    if (tmpnam(tmpfile) == NULL) {
        v->server_msg(v, "Failed to create temporary private key file", 1);
        return 1;
    } else {
        FILE *keyfile = fopen(tmpfile, "w");
        size_t keylen = sizeof(nx_default_private_key);
        if (!keyfile) {
            v->server_msg(v, "Failed to open temporary private key file", 1);
            return 1;
        }

        if (fwrite(nx_default_private_key, keylen-1, 1, keyfile) != 1) {
            v->server_msg(v, "Failed to write to temporary private key file", 1);
            return 1;
        }

        fclose(keyfile);

        v->server_msg(v, "Starting private key", 1);
        privkey = privatekey_from_file(v->session, tmpfile, NX_SSH_TYPE_DSS, "");
        v->server_msg(v, "Got private key from file", 1);
	pubkey = publickey_from_privatekey(privkey);
        v->server_msg(v, "Got public key from private key", 1);
        pubkeystr = publickey_to_string(pubkey);
        v->server_msg(v, "Got public key string from public key", 1);
        publickey_free(pubkey);

        unlink(tmpfile);
    }

    rc = ssh_connect(v->session);
    if (rc != SSH_OK) {
        //v->server_msg(v, "Failed to connect to SSH server %s", ssh_get_error(session));
        v->server_msg(v, "Failed to connect to SSH server", 0);
        ssh_free(v->session);
        return 1;
    } else {
        v->server_msg(v, "Connected to SSH server", 0);
    }
    
    
    rc = ssh_userauth_pubkey(v->session, NULL, pubkeystr, privkey);

    string_free(pubkeystr);
    privatekey_free(privkey);

    if (rc != SSH_AUTH_SUCCESS) {
        //v->server_msg(v, "Failed to auth to SSH server %s", ssh_get_error(session));
        v->server_msg(v, "Failed to auth to SSH server", 1);
        ssh_free(v->session);
        return 1;
    } else {
        v->server_msg(v, "Connected to SSH server", 0);
    }

    v->channel = ssh_channel_new(v->session);
    if (v->channel == NULL) {
        //v->server_msg(v, "Error creating channel %s", ssh_get_error(session));
        v->server_msg(v, "Error creating channel", 1);
        ssh_free(v->session);
        return 1;
    } else {
        v->server_msg(v, "Created channel", 0);
    }

    rc = ssh_channel_open_session(v->channel);
    if (rc != SSH_OK) {
        ssh_channel_free(v->channel);
        //v->server_msg(v, "Error opening channel: %s\n", ssh_get_error(session));
        v->server_msg(v, "Error opening channel", 1);
        return 1;
    } else {
        v->server_msg(v, "Opened channel", 0);
    }

    channel_request_shell(v->channel);

    session_send_command(v, "HELLO NXCLIENT - Version 3.5.0");
    v->server_msg(v, "Sent hello", 0);
    if (!get_expected_response(v, 105)) {
        v->server_msg(v, "Hello to NX server failed", 1);
        return 1;
    } else {
        v->server_msg(v, "Said hello", 0);
    }

    session_send_command(v, "SET SHELL_MODE SHELL");
    if (!get_expected_response(v, 105)) {
        v->server_msg(v, "Set shell mode failed", 1);
        return 1;
    } else {
        v->server_msg(v, "Set shell mode", 0);
    }

    session_send_command(v, "SET AUTH_MODE PASSWORD");
    if (!get_expected_response(v, 105)) {
        v->server_msg(v, "Set auth mode failed", 1);
        return 1;
    } else {
        v->server_msg(v, "Set auth mode", 0);
    }

    session_send_command(v, "login");
    if (!get_expected_response(v, 101)) {
        v->server_msg(v, "Login command failed", 1);
        return 1;
    } else {
        v->server_msg(v, "Login", 0);
    }

    session_send_command(v, v->username);
    if (!get_expected_response(v, 102)) {
        v->server_msg(v, "Sending username failed", 1);
        return 1;
    } else {
        v->server_msg(v, "Sent username", 0);
    }

    session_send_command(v, v->password);
    if (!get_expected_response(v, 105)) {
        v->server_msg(v, "Authentication failed", 1);
        return 1;
    } else {
        v->server_msg(v, "Auth OK", 0);
    }

    session_send_command(v, "listsession");
    if (!get_session(v, ip)) {
        v->server_msg(v, "Session listing failed", 1);
        return 1;
    } else {
        v->server_msg(v, "Listed sessions", 0);
    } 

    if (!v->sessiontoken) {
	v->server_msg(v, "Got no session", 0);
    } else {
	int do_restore = 1;

	if (ip[0] == '-') {
            /* no session */
	    do_restore = 1;
	} else if (g_strcmp(ip, "127.0.0.1") == 0) {
            /* local session already running */
	    v->server_msg(v, "NXProxy already running", 0);
	    do_restore = 0;
	} else {
            /* another remote session */
	    char disconnectcommand[1024];

	    sprintf(disconnectcommand, "disconnect --sessionid=\"%s\"", v->sessiontoken);
	    session_send_command(v, disconnectcommand);
	    if (!get_expected_response_long(v, 105)) {
		v->server_msg(v, "Disconnect failed", 1);
		return 1;
	    } else {
		v->server_msg(v, "Disconnect", 0);
	    }

	    do_restore = 1;
	}

	if (do_restore) {
	    char sessioncommand[1024];

	    sprintf(sessioncommand, "restoresession --session=\"%s\" --id=\"%s\" --type=\"unix-application\" --app=\"startxfce4\" --geometry=\"%dx%dx24\" --client=\"linux\" --cache=\"16M\" --images=\"64M\" --link=\"modem\" --encryption=\"0\" --render=\"0\" --backingstore=\"1\"", v->username, v->sessiontoken, v->server_width, v->server_height);
	    session_send_command(v, sessioncommand);
	    get_session_info(v);

	    v->nxproxy = fork();
	    if (v->nxproxy > 0) {
		    v->server_msg(v, "Forked NXProxy", 1);
	    } else if (v->nxproxy == 0) {
		    char sessionstash[512];
		    sprintf(sessionstash, "nx,session=%s,cookie=%s,id=%s,shmem=1,shpix=1,connect=%s:%d", v->username, v->cookie, v->sessionid, "127.0.0.1", v->display);
		    v->server_msg(v, sessionstash, 1);
		    //execl("/usr/bin/nxproxy", "/usr/bin/nxproxy", "-S", sessionstash, NULL);
		    execl("/usr/bin/xvfb-run", "/usr/bin/xvfb-run", "-s", "-screen 0 1024x768x24 -pixdepths 1 4 8 15 16 24 32 -fbdir /var/tmp", "/usr/bin/nxproxy", "-S", sessionstash, NULL);
	    } else {
		    v->server_msg(v, "NXProxy fork failed", 1);
		    return 1;
	    }
	}
    }


/*
    session_send_command(v, "bye");
    if (!get_expected_response(v, 999)) {
        v->server_msg(v, "Goodbye failed", 1);
        return 1;
    } else {
        v->server_msg(v, "Sent goodbye", 0);
    }
*/

    /* begin VNC connection */
    v->server_msg(v, "VNC started connecting", 0);
    check_sec_result = 1;

    /* only support 8 and 16 bpp connections from rdp client */
    if ((v->server_bpp != 8) && (v->server_bpp != 15) &&
            (v->server_bpp != 16) && (v->server_bpp != 24))
    {
        v->server_msg(v, "VNC error - only supporting 8, 15, 16 and 24 bpp rdp "
                      "connections", 0);
        return 1;
    }

    if (g_strcmp(v->ip, "") == 0)
    {
        v->server_msg(v, "VNC error - no ip set", 0);
        return 1;
    }

    make_stream(s);
    g_sprintf(con_port, "%s", v->port);
    make_stream(pixel_format);
    v->sck = g_tcp_socket();
    v->sck_obj = g_create_wait_obj_from_socket(v->sck, 0);
    v->sck_closed = 0;
    g_sprintf(text, "VNC connecting to %s %s", v->ip, con_port);
    v->server_msg(v, text, 0);
    error = g_tcp_connect(v->sck, v->ip, con_port);

    if (error == 0)
    {
        v->server_msg(v, "VNC tcp connected", 0);
        g_tcp_set_non_blocking(v->sck);
        g_tcp_set_no_delay(v->sck);
        /* protocal version */
        init_stream(s, 8192);
        error = lib_recv(v, s->data, 12);

        if (error == 0)
        {
            error = lib_send(v, "RFB 003.003\n", 12);
        }

        /* sec type */
        if (error == 0)
        {
            init_stream(s, 8192);
            error = lib_recv(v,  s->data, 4);
        }

        if (error == 0)
        {
            in_uint32_be(s, i);
            g_sprintf(text, "VNC security level is %d (1 = none, 2 = standard)", i);
            v->server_msg(v, text, 0);

            if (i == 1) /* none */
            {
                check_sec_result = 0;
            }
            else if (i == 2) /* dec the password and the server random */
            {
                init_stream(s, 8192);
                error = lib_recv(v, s->data, 16);

                if (error == 0)
                {
                    rfbEncryptBytes(s->data, v->password);
                    error = lib_send(v, s->data, 16);
                    check_sec_result = 1; // not needed
                }
            }
            else if (i == 0)
            {
                log_message(LOG_LEVEL_DEBUG, "VNC Server will disconnect");
                error = 1;
            }
            else
            {
                log_message(LOG_LEVEL_DEBUG, "VNC unsupported security level");
                error = 1;
            }
        }
    }

    if (error != 0)
    {
        log_message(LOG_LEVEL_DEBUG, "VNC Error after security negotiation");
    }

    if (error == 0 && check_sec_result)
    {
        /* sec result */
        init_stream(s, 8192);
        error = lib_recv(v, s->data, 4);

        if (error == 0)
        {
            in_uint32_be(s, i);

            if (i != 0)
            {
                v->server_msg(v, "VNC password failed", 0);
                error = 2;
            }
            else
            {
                v->server_msg(v, "VNC password ok", 0);
            }
        }
    }

    if (error == 0)
    {
        v->server_msg(v, "VNC sending share flag", 0);
        init_stream(s, 8192);
        s->data[0] = 1;
        error = lib_send(v, s->data, 1); /* share flag */
    }
    else
    {
        log_message(LOG_LEVEL_DEBUG, "VNC error before sending share flag");
    }

    if (error == 0)
    {
        v->server_msg(v, "VNC receiving server init", 0);
        error = lib_recv(v, s->data, 4); /* server init */
    }
    else
    {
        log_message(LOG_LEVEL_DEBUG, "VNC error before receiving server init");
    }

    if (error == 0)
    {
        in_uint16_be(s, v->mod_width);
        in_uint16_be(s, v->mod_height);
        init_stream(pixel_format, 8192);
        v->server_msg(v, "VNC receiving pixel format", 0);
        error = lib_recv(v, pixel_format->data, 16);
    }
    else
    {
        log_message(LOG_LEVEL_DEBUG, "VNC error before receiving pixel format");
    }

    if (error == 0)
    {
        v->mod_bpp = v->server_bpp;
        init_stream(s, 8192);
        v->server_msg(v, "VNC receiving name length", 0);
        error = lib_recv(v, s->data, 4); /* name len */
    }
    else
    {
        log_message(LOG_LEVEL_DEBUG, "VNC error before receiving name length");
    }

    if (error == 0)
    {
        in_uint32_be(s, i);

        if (i > 255 || i < 0)
        {
            error = 3;
        }
        else
        {
            v->server_msg(v, "VNC receiving name", 0);
            error = lib_recv(v, v->mod_name, i);
            v->mod_name[i] = 0;
        }
    }
    else
    {
        log_message(LOG_LEVEL_DEBUG, "VNC error before receiving name");
    }

    /* should be connected */
    if (error == 0)
    {
        /* SetPixelFormat */
        init_stream(s, 8192);
        out_uint8(s, 0);
        out_uint8(s, 0);
        out_uint8(s, 0);
        out_uint8(s, 0);
        init_stream(pixel_format, 8192);

        if (v->mod_bpp == 8)
        {
            out_uint8(pixel_format, 8); /* bits per pixel */
            out_uint8(pixel_format, 8); /* depth */
#if defined(B_ENDIAN)
            out_uint8(pixel_format, 1); /* big endian */
#else
            out_uint8(pixel_format, 0); /* big endian */
#endif
            out_uint8(pixel_format, 0); /* true color flag */
            out_uint16_be(pixel_format, 0); /* red max */
            out_uint16_be(pixel_format, 0); /* green max */
            out_uint16_be(pixel_format, 0); /* blue max */
            out_uint8(pixel_format, 0); /* red shift */
            out_uint8(pixel_format, 0); /* green shift */
            out_uint8(pixel_format, 0); /* blue shift */
            out_uint8s(pixel_format, 3); /* pad */
        }
        else if (v->mod_bpp == 15)
        {
            out_uint8(pixel_format, 16); /* bits per pixel */
            out_uint8(pixel_format, 15); /* depth */
#if defined(B_ENDIAN)
            out_uint8(pixel_format, 1); /* big endian */
#else
            out_uint8(pixel_format, 0); /* big endian */
#endif
            out_uint8(pixel_format, 1); /* true color flag */
            out_uint16_be(pixel_format, 31); /* red max */
            out_uint16_be(pixel_format, 31); /* green max */
            out_uint16_be(pixel_format, 31); /* blue max */
            out_uint8(pixel_format, 10); /* red shift */
            out_uint8(pixel_format, 5); /* green shift */
            out_uint8(pixel_format, 0); /* blue shift */
            out_uint8s(pixel_format, 3); /* pad */
        }
        else if (v->mod_bpp == 16)
        {
            out_uint8(pixel_format, 16); /* bits per pixel */
            out_uint8(pixel_format, 16); /* depth */
#if defined(B_ENDIAN)
            out_uint8(pixel_format, 1); /* big endian */
#else
            out_uint8(pixel_format, 0); /* big endian */
#endif
            out_uint8(pixel_format, 1); /* true color flag */
            out_uint16_be(pixel_format, 31); /* red max */
            out_uint16_be(pixel_format, 63); /* green max */
            out_uint16_be(pixel_format, 31); /* blue max */
            out_uint8(pixel_format, 11); /* red shift */
            out_uint8(pixel_format, 5); /* green shift */
            out_uint8(pixel_format, 0); /* blue shift */
            out_uint8s(pixel_format, 3); /* pad */
        }
        else if (v->mod_bpp == 24)
        {
            out_uint8(pixel_format, 32); /* bits per pixel */
            out_uint8(pixel_format, 24); /* depth */
#if defined(B_ENDIAN)
            out_uint8(pixel_format, 1); /* big endian */
#else
            out_uint8(pixel_format, 0); /* big endian */
#endif
            out_uint8(pixel_format, 1); /* true color flag */
            out_uint16_be(pixel_format, 255); /* red max */
            out_uint16_be(pixel_format, 255); /* green max */
            out_uint16_be(pixel_format, 255); /* blue max */
            out_uint8(pixel_format, 16); /* red shift */
            out_uint8(pixel_format, 8); /* green shift */
            out_uint8(pixel_format, 0); /* blue shift */
            out_uint8s(pixel_format, 3); /* pad */
        }

        out_uint8a(s, pixel_format->data, 16);
        v->server_msg(v, "VNC sending pixel format", 0);
        error = lib_send(v, s->data, 20);
    }

    if (error == 0)
    {
        /* SetEncodings */
        init_stream(s, 8192);
        out_uint8(s, 2);
        out_uint8(s, 0);
        out_uint16_be(s, 4);
        out_uint32_be(s, 0); /* raw */
        out_uint32_be(s, 1); /* copy rect */
        out_uint32_be(s, 0xffffff11); /* cursor */
        out_uint32_be(s, 0xffffff21); /* desktop size */
        v->server_msg(v, "VNC sending encodings", 0);
        error = lib_send(v, s->data, 4 + 4 * 4);
    }

    if (error == 0)
    {
        error = v->server_reset(v, v->mod_width, v->mod_height, v->mod_bpp);
    }

    if (error == 0)
    {
        /* FrambufferUpdateRequest */
        init_stream(s, 8192);
        out_uint8(s, 3);
        out_uint8(s, 0);
        out_uint16_be(s, 0);
        out_uint16_be(s, 0);
        out_uint16_be(s, v->mod_width);
        out_uint16_be(s, v->mod_height);
        v->server_msg(v, "VNC sending framebuffer update request", 0);
        error = lib_send(v, s->data, 10);
    }

    if (error == 0)
    {
        if (v->server_bpp != v->mod_bpp)
        {
            v->server_msg(v, "VNC error - server bpp and client bpp do not match", 0);
            error = 1;
        }
    }

    if (error == 0)
    {
        /* set almost null cursor, this is the little dot cursor */
        g_memset(cursor_data, 0, 32 * (32 * 3));
        g_memset(cursor_data + (32 * (32 * 3) - 1 * 32 * 3), 0xff, 9);
        g_memset(cursor_data + (32 * (32 * 3) - 2 * 32 * 3), 0xff, 9);
        g_memset(cursor_data + (32 * (32 * 3) - 3 * 32 * 3), 0xff, 9);
        g_memset(cursor_mask, 0xff, 32 * (32 / 8));
        v->server_msg(v, "VNC sending cursor", 0);
        error = v->server_set_cursor(v, 3, 3, cursor_data, cursor_mask);
    }

    free_stream(s);
    free_stream(pixel_format);

    if (error == 0)
    {
        v->server_msg(v, "VNC connection complete, connected ok", 0);
        lib_open_clip_channel(v);
    }
    else
    {
        v->server_msg(v, "VNC error - problem connecting", 0);
    }

    return error;
}

/******************************************************************************/
int DEFAULT_CC
lib_mod_end(struct nxvnc *v)
{
    if (v->vnc_desktop != 0)
    {
    }

    g_free(v->clip_data);
    v->clip_data = 0;
    v->clip_data_size = 0;
    return 0;
}

/******************************************************************************/
int DEFAULT_CC
lib_mod_set_param(struct nxvnc *v, char *name, char *value)
{
    if (g_strcasecmp(name, "username") == 0)
    {
        g_strncpy(v->username, value, 255);
    }
    else if (g_strcasecmp(name, "password") == 0)
    {
        g_strncpy(v->password, value, 255);
    }
    else if (g_strcasecmp(name, "ip") == 0)
    {
        g_strncpy(v->ip, value, 255);
    }
    else if (g_strcasecmp(name, "port") == 0)
    {
        g_strncpy(v->port, value, 255);
    }
    else if (g_strcasecmp(name, "keylayout") == 0)
    {
        v->keylayout = g_atoi(value);
    }

    return 0;
}

/******************************************************************************/
/* return error */
int DEFAULT_CC
lib_mod_get_wait_objs(struct nxvnc *v, tbus *read_objs, int *rcount,
                      tbus *write_objs, int *wcount, int *timeout)
{
    int i;

    i = *rcount;

    if (v != 0)
    {
        if (v->sck_obj != 0)
        {
            read_objs[i++] = v->sck_obj;
        }
    }

    *rcount = i;
    return 0;
}

/******************************************************************************/
/* return error */
int DEFAULT_CC
lib_mod_check_wait_objs(struct nxvnc *v)
{
    int rv;

    rv = 0;

    if (v != 0)
    {
        if (v->sck_obj != 0)
        {
            if (g_is_wait_obj_set(v->sck_obj))
            {
                rv = lib_mod_signal(v);
            }
        }
    }

    return rv;
}

/******************************************************************************/
struct nxvnc *EXPORT_CC
mod_init(void)
{
    struct nxvnc *v;

    v = (struct nxvnc *)g_malloc(sizeof(struct nxvnc), 1);
    /* set client functions */
    v->size = sizeof(struct nxvnc);
    v->version = CURRENT_MOD_VER;
    v->handle = (long)v;
    v->mod_connect = lib_mod_connect;
    v->mod_start = lib_mod_start;
    v->mod_event = lib_mod_event;
    v->mod_signal = lib_mod_signal;
    v->mod_end = lib_mod_end;
    v->mod_set_param = lib_mod_set_param;
    v->mod_get_wait_objs = lib_mod_get_wait_objs;
    v->mod_check_wait_objs = lib_mod_check_wait_objs;

    v->nxproxy = -1;

    return v;
}

/******************************************************************************/
int EXPORT_CC
mod_exit(struct nxvnc *v)
{
    log_message(LOG_LEVEL_DEBUG, "NX-VNC mod_exit");

    if (v == 0)
    {
        return 0;
    }

/*
    ssh_channel_close(v->channel);
    ssh_channel_send_eof(v->channel);
    ssh_channel_free(v->channel);

    ssh_disconnect(v->session);
    ssh_free(v->session);
*/

    if (v->sessiontoken) {
	/*
        char disconnectcommand[1024];

        sprintf(disconnectcommand, "disconnect --sessionid=\"%s\"", v->sessiontoken);

        session_send_command(v, disconnectcommand);
	if (!get_expected_response(v, 900)) {
	    v->server_msg(v, "Disconnect failed", 1);
	    return 1;
	} else {
	    v->server_msg(v, "Disconnect", 0);
	}
	*/
    }

    g_delete_wait_obj_from_socket(v->sck_obj);
    g_tcp_close(v->sck);
    g_free(v);

    return 0;
}
