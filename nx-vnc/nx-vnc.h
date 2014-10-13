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

/* include other h files */
#include "arch.h"
#include "parse.h"
#include "os_calls.h"
#include "d3des.h"
#include "defines.h"

#include <libssh/libssh.h>

#define CURRENT_MOD_VER 2

struct nxvnc
{
  int size; /* size of this struct */
  int version; /* internal version */
  /* client functions */
  int (*mod_start)(struct nxvnc* v, int w, int h, int bpp);
  int (*mod_connect)(struct nxvnc* v);
  int (*mod_event)(struct nxvnc* v, int msg, long param1, long param2,
                   long param3, long param4);
  int (*mod_signal)(struct nxvnc* v);
  int (*mod_end)(struct nxvnc* v);
  int (*mod_set_param)(struct nxvnc* v, char* name, char* value);
  int (*mod_session_change)(struct nxvnc* v, int, int);
  int (*mod_get_wait_objs)(struct nxvnc* v, tbus* read_objs, int* rcount,
                           tbus* write_objs, int* wcount, int* timeout);
  int (*mod_check_wait_objs)(struct nxvnc* v);
  long mod_dumby[100 - 9]; /* align, 100 minus the number of mod
                              functions above */
  /* server functions */
  int (*server_begin_update)(struct nxvnc* v);
  int (*server_end_update)(struct nxvnc* v);
  int (*server_fill_rect)(struct nxvnc* v, int x, int y, int cx, int cy);
  int (*server_screen_blt)(struct nxvnc* v, int x, int y, int cx, int cy,
                           int srcx, int srcy);
  int (*server_paint_rect)(struct nxvnc* v, int x, int y, int cx, int cy,
                           char* data, int width, int height, int srcx, int srcy);
  int (*server_set_cursor)(struct nxvnc* v, int x, int y, char* data, char* mask);
  int (*server_palette)(struct nxvnc* v, int* palette);
  int (*server_msg)(struct nxvnc* v, char* msg, int code);
  int (*server_is_term)(struct nxvnc* v);
  int (*server_set_clip)(struct nxvnc* v, int x, int y, int cx, int cy);
  int (*server_reset_clip)(struct nxvnc* v);
  int (*server_set_fgcolor)(struct nxvnc* v, int fgcolor);
  int (*server_set_bgcolor)(struct nxvnc* v, int bgcolor);
  int (*server_set_opcode)(struct nxvnc* v, int opcode);
  int (*server_set_mixmode)(struct nxvnc* v, int mixmode);
  int (*server_set_brush)(struct nxvnc* v, int x_orgin, int y_orgin,
                          int style, char* pattern);
  int (*server_set_pen)(struct nxvnc* v, int style,
                        int width);
  int (*server_draw_line)(struct nxvnc* v, int x1, int y1, int x2, int y2);
  int (*server_add_char)(struct nxvnc* v, int font, int charactor,
                         int offset, int baseline,
                         int width, int height, char* data);
  int (*server_draw_text)(struct nxvnc* v, int font,
                          int flags, int mixmode, int clip_left, int clip_top,
                          int clip_right, int clip_bottom,
                          int box_left, int box_top,
                          int box_right, int box_bottom,
                          int x, int y, char* data, int data_len);
  int (*server_reset)(struct nxvnc* v, int width, int height, int bpp);
  int (*server_query_channel)(struct nxvnc* v, int index,
                              char* channel_name,
                              int* channel_flags);
  int (*server_get_channel_id)(struct nxvnc* v, char* name);
  int (*server_send_to_channel)(struct nxvnc* v, int channel_id,
                                char* data, int data_len,
                                int total_data_len, int flags);
  int (*server_bell_trigger)(struct nxvnc* v);
  long server_dumby[100 - 25]; /* align, 100 minus the number of server
                                  functions above */
  /* common */
  long handle; /* pointer to self as long */
  long wm;
  long painter;
  int sck;
  /* mod data */
  int server_width;
  int server_height;
  int server_bpp;
  int mod_width;
  int mod_height;
  int mod_bpp;
  char mod_name[256];
  int mod_mouse_state;
  int palette[256];
  int vnc_desktop;
  char username[256];
  char password[256];
  char ip[256];
  char port[256];
  int sck_closed;
  int shift_state; /* 0 up, 1 down */
  int keylayout;
  int clip_chanid;
  char* clip_data;
  int clip_data_size;
  tbus sck_obj;

  /* ssh handling */
  ssh_session session;
  ssh_channel channel;

  /* nx data */
  int display;
  char *sessionid;
  char *sessiontoken;
  char *cookie;
};
