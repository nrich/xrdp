/**
 * xrdp: A Remote Desktop Protocol server.
 *
 * Copyright (C) Jay Sorg 2009-2013
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
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <signal.h>
#include <sys/un.h>

#ifdef XRDP_LOAD_PULSE_MODULES
#include <pulse/util.h>
#endif

#include "sound.h"
#include "thread_calls.h"
#include "defines.h"
#include "fifo.h"

extern int g_rdpsnd_chan_id;    /* in chansrv.c */
extern int g_display_num;       /* in chansrv.c */

/* audio out: sound_server -> xrdp -> NeutrinoRDP */
static struct trans *g_audio_l_trans_out = 0; /* listener */
static struct trans *g_audio_c_trans_out = 0; /* connection */

/* audio in:  sound_server <- xrdp <- NeutrinoRDP */
static struct trans *g_audio_l_trans_in = 0;  /* listener */
static struct trans *g_audio_c_trans_in = 0;  /* connection */

static int    g_training_sent_time = 0;
static int    g_cBlockNo = 0;
static int    g_bytes_in_stream = 0;
static FIFO   in_fifo;

static struct stream *g_stream_inp = NULL;

#define BBUF_SIZE (1024 * 8)
char g_buffer[BBUF_SIZE];
int g_buf_index = 0;
int g_sent_time[256];
int g_sent_flag[256];

#if defined(XRDP_SIMPLESOUND)
static void *DEFAULT_CC
read_raw_audio_data(void *arg);
#endif

#define CHANSRV_PORT_OUT_STR  "/tmp/.xrdp/xrdp_chansrv_audio_out_socket_%d"
#define CHANSRV_PORT_IN_STR   "/tmp/.xrdp/xrdp_chansrv_audio_in_socket_%d"

#define HQ_AUDIO 0

struct xr_wave_format_ex
{
    int wFormatTag;
    int nChannels;
    int nSamplesPerSec;
    int nAvgBytesPerSec;
    int nBlockAlign;
    int wBitsPerSample;
    int cbSize;
    char *data;
};

/* output formats */

static char g_pcm_22050_data[] = { 0 };
static struct xr_wave_format_ex g_pcm_22050 =
{
    1,               /* wFormatTag - WAVE_FORMAT_PCM */
    2,               /* num of channels */
    22050,           /* samples per sec */
    88200,           /* avg bytes per sec */
    4,               /* block align */
    16,              /* bits per sample */
    0,               /* data size */
    g_pcm_22050_data /* data */
};

static char g_pcm_44100_data[] = { 0 };
static struct xr_wave_format_ex g_pcm_44100 =
{
    1,               /* wFormatTag - WAVE_FORMAT_PCM */
    2,               /* num of channels */
    44100,           /* samples per sec */
    176400,          /* avg bytes per sec */
    4,               /* block align */
    16,              /* bits per sample */
    0,               /* data size */
    g_pcm_44100_data /* data */
};

#define SND_NUM_OUTP_FORMATS 2
static struct xr_wave_format_ex *g_wave_outp_formats[SND_NUM_OUTP_FORMATS] =
{
    &g_pcm_44100,
    &g_pcm_22050
};

/* index into list from client */
static int g_current_client_format_index = 0;

/* index into list from server */
static int g_current_server_format_index = 0;

/* input formats */

static char g_pcm_inp_22050_data[] = { 0 };
static struct xr_wave_format_ex g_pcm_inp_22050 =
{
    1,               /* wFormatTag - WAVE_FORMAT_PCM */
    2,               /* num of channels */
    22050,           /* samples per sec */
    88200,           /* avg bytes per sec */
    4,               /* block align */
    16,              /* bits per sample */
    0,               /* data size */
    g_pcm_inp_22050_data /* data */
};

static char g_pcm_inp_44100_data[] = { 0 };
static struct xr_wave_format_ex g_pcm_inp_44100 =
{
    1,               /* wFormatTag - WAVE_FORMAT_PCM */
    2,               /* num of channels */
    44100,           /* samples per sec */
    176400,          /* avg bytes per sec */
    4,               /* block align */
    16,              /* bits per sample */
    0,               /* data size */
    g_pcm_inp_44100_data /* data */
};

#define SND_NUM_INP_FORMATS 2
static struct xr_wave_format_ex *g_wave_inp_formats[SND_NUM_INP_FORMATS] =
{
    &g_pcm_inp_22050,
    &g_pcm_inp_44100
};

static int g_client_input_format_index = 0;
static int g_server_input_format_index = 0;

/*****************************************************************************/
static int APP_CC
sound_send_server_output_formats(void)
{
    struct stream *s;
    int bytes;
    int index;
    char *size_ptr;

    make_stream(s);
    init_stream(s, 8182);
    out_uint16_le(s, SNDC_FORMATS);
    size_ptr = s->p;
    out_uint16_le(s, 0);                    /* size, set later */
    out_uint32_le(s, 0);                    /* dwFlags */
    out_uint32_le(s, 0);                    /* dwVolume */
    out_uint32_le(s, 0);                    /* dwPitch */
    out_uint16_le(s, 0);                    /* wDGramPort */
    out_uint16_le(s, SND_NUM_OUTP_FORMATS); /* wNumberOfFormats */
    out_uint8(s, g_cBlockNo);               /* cLastBlockConfirmed */
    out_uint16_le(s, 2);                    /* wVersion */
    out_uint8(s, 0);                        /* bPad */

    /* sndFormats */
    /*
        wFormatTag      2 byte offset 0
        nChannels       2 byte offset 2
        nSamplesPerSec  4 byte offset 4
        nAvgBytesPerSec 4 byte offset 8
        nBlockAlign     2 byte offset 12
        wBitsPerSample  2 byte offset 14
        cbSize          2 byte offset 16
        data            variable offset 18
    */

    /*  examples
        01 00 02 00 44 ac 00 00 10 b1 02 00 04 00 10 00 ....D...........
        00 00
        01 00 02 00 22 56 00 00 88 58 01 00 04 00 10 00 ...."V...X......
        00 00
    */

    for (index = 0; index < SND_NUM_OUTP_FORMATS; index++)
    {
        out_uint16_le(s, g_wave_outp_formats[index]->wFormatTag);
        out_uint16_le(s, g_wave_outp_formats[index]->nChannels);
        out_uint32_le(s, g_wave_outp_formats[index]->nSamplesPerSec);
        out_uint32_le(s, g_wave_outp_formats[index]->nAvgBytesPerSec);
        out_uint16_le(s, g_wave_outp_formats[index]->nBlockAlign);
        out_uint16_le(s, g_wave_outp_formats[index]->wBitsPerSample);
        bytes = g_wave_outp_formats[index]->cbSize;
        out_uint16_le(s, bytes);
        if (bytes > 0)
        {
            out_uint8p(s, g_wave_outp_formats[index]->data, bytes);
        }
    }

    s_mark_end(s);
    bytes = (int)((s->end - s->data) - 4);
    size_ptr[0] = bytes;
    size_ptr[1] = bytes >> 8;
    bytes = (int)(s->end - s->data);
    send_channel_data(g_rdpsnd_chan_id, s->data, bytes);
    free_stream(s);
    return 0;
}

/*****************************************************************************/

static int
sound_send_training(void)
{
    struct stream *s;
    int bytes;
    int time;
    char *size_ptr;

    make_stream(s);
    init_stream(s, 8182);
    out_uint16_le(s, SNDC_TRAINING);
    size_ptr = s->p;
    out_uint16_le(s, 0); /* size, set later */
    time = g_time2();
    g_training_sent_time = time;
    out_uint16_le(s, time);
    out_uint16_le(s, 1024);
    out_uint8s(s, (1024 - 4));
    s_mark_end(s);
    bytes = (int)((s->end - s->data) - 4);
    size_ptr[0] = bytes;
    size_ptr[1] = bytes >> 8;
    bytes = (int)(s->end - s->data);
    send_channel_data(g_rdpsnd_chan_id, s->data, bytes);
    free_stream(s);
    return 0;
}

/*****************************************************************************/
static int APP_CC
sound_process_output_format(int aindex, int wFormatTag, int nChannels,
                            int nSamplesPerSec, int nAvgBytesPerSec,
                            int nBlockAlign, int wBitsPerSample,
                            int cbSize, char *data)
{
    LOG(1, ("sound_process_output_format:"));
    LOG(1, ("      wFormatTag      %d", wFormatTag));
    LOG(1, ("      nChannels       %d", nChannels));
    LOG(1, ("      nSamplesPerSec  %d", nSamplesPerSec));
    LOG(1, ("      nAvgBytesPerSec %d", nAvgBytesPerSec));
    LOG(1, ("      nBlockAlign     %d", nBlockAlign));
    LOG(1, ("      wBitsPerSample  %d", wBitsPerSample));
    LOG(1, ("      cbSize          %d", cbSize));

    g_hexdump(data, cbSize);
#if HQ_AUDIO
    /* select CD quality audio */
    if (wFormatTag == g_pcm_44100.wFormatTag &&
        nChannels == g_pcm_44100.nChannels &&
        nSamplesPerSec == g_pcm_44100.nSamplesPerSec &&
        nAvgBytesPerSec == g_pcm_44100.nAvgBytesPerSec &&
        nBlockAlign == g_pcm_44100.nBlockAlign &&
        wBitsPerSample == g_pcm_44100.wBitsPerSample)
    {
        g_current_client_format_index = aindex;
        g_current_server_format_index = 0;
    }
#else
    if (wFormatTag == g_pcm_22050.wFormatTag &&
        nChannels == g_pcm_22050.nChannels &&
        nSamplesPerSec == g_pcm_22050.nSamplesPerSec &&
        nAvgBytesPerSec == g_pcm_22050.nAvgBytesPerSec &&
        nBlockAlign == g_pcm_22050.nBlockAlign &&
        wBitsPerSample == g_pcm_22050.wBitsPerSample)
    {
        g_current_client_format_index = aindex;
        g_current_server_format_index = 0;
    }
#endif

#if 0
    for (lindex = 0; lindex < NUM_BUILT_IN; lindex++)
    {
        if (wFormatTag == g_wave_formats[lindex]->wFormatTag &&
            nChannels == g_wave_formats[lindex]->nChannels &&
            nSamplesPerSec == g_wave_formats[lindex]->nSamplesPerSec &&
            nAvgBytesPerSec == g_wave_formats[lindex]->nAvgBytesPerSec &&
            nBlockAlign == g_wave_formats[lindex]->nBlockAlign &&
            wBitsPerSample == g_wave_formats[lindex]->wBitsPerSample)
        {
            g_current_client_format_index = aindex;
            g_current_server_format_index = lindex;
        }
    }
#endif
    return 0;
}

/*****************************************************************************/
/*
    0000 07 02 26 00 03 00 80 00 ff ff ff ff 00 00 00 00 ..&.............
    0010 00 00 01 00 00 02 00 00 01 00 02 00 44 ac 00 00 ............D...
    0020 10 b1 02 00 04 00 10 00 00 00
*/

static int APP_CC
sound_process_output_formats(struct stream *s, int size)
{
    int num_formats;
    int index;
    int wFormatTag;
    int nChannels;
    int nSamplesPerSec;
    int nAvgBytesPerSec;
    int nBlockAlign;
    int wBitsPerSample;
    int cbSize;
    char *data;

    if (size < 16)
        return 1;

    in_uint8s(s, 14);
    in_uint16_le(s, num_formats);
    in_uint8s(s, 4);

    if (num_formats > 0)
    {
        for (index = 0; index < num_formats; index++)
        {
            in_uint16_le(s, wFormatTag);
            in_uint16_le(s, nChannels);
            in_uint32_le(s, nSamplesPerSec);
            in_uint32_le(s, nAvgBytesPerSec);
            in_uint16_le(s, nBlockAlign);
            in_uint16_le(s, wBitsPerSample);
            in_uint16_le(s, cbSize);
            in_uint8p(s, data, cbSize);
            sound_process_output_format(index, wFormatTag, nChannels, nSamplesPerSec,
                                        nAvgBytesPerSec, nBlockAlign, wBitsPerSample,
                                        cbSize, data);
        }
        sound_send_training();
    }

    return 0;
}

/*****************************************************************************/
/* send wave message to client */
static int
sound_send_wave_data_chunk(char *data, int data_bytes)
{
    struct stream *s;
    int bytes;
    int time;
    char *size_ptr;

    LOG(10, ("sound_send_wave_data_chunk: data_bytes %d", data_bytes));

    if ((data_bytes < 4) || (data_bytes > 128 * 1024))
    {
        LOG(0, ("sound_send_wave_data_chunk: bad data_bytes %d", data_bytes));
        return 0;
    }

    if (g_sent_flag[(g_cBlockNo + 1) & 0xff] & 1)
    {
        LOG(10, ("sound_send_wave_data_chunk: no room"));
        return 0;
    }
    else
    {
        LOG(10, ("sound_send_wave_data_chunk: got room"));
    }

    /* part one of 2 PDU wave info */

    LOG(10, ("sound_send_wave_data_chunk: sending %d bytes", data_bytes));

    make_stream(s);
    init_stream(s, 16 + data_bytes); /* some extra space */
    out_uint16_le(s, SNDC_WAVE);
    size_ptr = s->p;
    out_uint16_le(s, 0); /* size, set later */
    time = g_time2();
    out_uint16_le(s, time);
    out_uint16_le(s, g_current_client_format_index); /* wFormatNo */
    g_cBlockNo++;
    out_uint8(s, g_cBlockNo);
    g_sent_time[g_cBlockNo & 0xff] = time;
    g_sent_flag[g_cBlockNo & 0xff] = 1;

    LOG(10, ("sound_send_wave_data_chunk: sending time %d, g_cBlockNo %d",
             time & 0xffff, g_cBlockNo & 0xff));

    out_uint8s(s, 3);
    out_uint8a(s, data, 4);
    s_mark_end(s);
    bytes = (int)((s->end - s->data) - 4);
    bytes += data_bytes;
    bytes -= 4;
    size_ptr[0] = bytes;
    size_ptr[1] = bytes >> 8;
    bytes = (int)(s->end - s->data);
    send_channel_data(g_rdpsnd_chan_id, s->data, bytes);

    /* part two of 2 PDU wave info
       even is zero, we have to send this */
    init_stream(s, data_bytes);
    out_uint32_le(s, 0);
    out_uint8a(s, data + 4, data_bytes - 4);
    s_mark_end(s);
    bytes = (int)(s->end - s->data);
    send_channel_data(g_rdpsnd_chan_id, s->data, bytes);

    free_stream(s);
    return 0;
}

/*****************************************************************************/
/* send wave message to client, buffer first */
static int
sound_send_wave_data(char *data, int data_bytes)
{
    int space_left;
    int chunk_bytes;
    int data_index;

    LOG(10, ("sound_send_wave_data: sending %d bytes", data_bytes));
    data_index = 0;
    while (data_bytes > 0)
    {
        space_left = BBUF_SIZE - g_buf_index;
        chunk_bytes = MIN(space_left, data_bytes);
        if (chunk_bytes < 1)
        {
            LOG(10, ("sound_send_wave_data: error"));
            break;
        }
        g_memcpy(g_buffer + g_buf_index, data + data_index, chunk_bytes);
        g_buf_index += chunk_bytes;
        if (g_buf_index >= BBUF_SIZE)
        {
            sound_send_wave_data_chunk(g_buffer, BBUF_SIZE);
            g_buf_index = 0;
        }
        data_bytes -= chunk_bytes;
        data_index += chunk_bytes;
    }
    return 0;
}

/*****************************************************************************/
/* send close message to client */
static int
sound_send_close(void)
{
    struct stream *s;
    int bytes;
    char *size_ptr;

    LOG(10, ("sound_send_close:"));

    /* send any left over data */
    sound_send_wave_data_chunk(g_buffer, g_buf_index);
    g_buf_index = 0;

    make_stream(s);
    init_stream(s, 8182);
    out_uint16_le(s, SNDC_CLOSE);
    size_ptr = s->p;
    out_uint16_le(s, 0); /* size, set later */
    s_mark_end(s);
    bytes = (int)((s->end - s->data) - 4);
    size_ptr[0] = bytes;
    size_ptr[1] = bytes >> 8;
    bytes = (int)(s->end - s->data);
    send_channel_data(g_rdpsnd_chan_id, s->data, bytes);
    free_stream(s);
    return 0;
}

/*****************************************************************************/
/* from client */
static int APP_CC
sound_process_training(struct stream *s, int size)
{
    int time_diff;

    time_diff = g_time2() - g_training_sent_time;
    LOG(0, ("sound_process_training: round trip time %u", time_diff));
    return 0;
}

/*****************************************************************************/
/* from client */
static int APP_CC
sound_process_wave_confirm(struct stream *s, int size)
{
    int wTimeStamp;
    int cConfirmedBlockNo;
    int time;
    int time_diff;

    time = g_time2();
    in_uint16_le(s, wTimeStamp);
    in_uint8(s, cConfirmedBlockNo);
    time_diff = time - g_sent_time[cConfirmedBlockNo & 0xff];
    g_sent_flag[cConfirmedBlockNo & 0xff] &= ~1;

    LOG(10, ("sound_process_wave_confirm: wTimeStamp %d, "
        "cConfirmedBlockNo %d time diff %d",
        wTimeStamp, cConfirmedBlockNo, time_diff));

    return 0;
}

/*****************************************************************************/
/* process message in from the audio source, eg pulse, alsa
   on it's way to the client */
static int APP_CC
process_pcm_message(int id, int size, struct stream *s)
{
    switch (id)
    {
        case 0:
            sound_send_wave_data(s->p, size);
            break;
        case 1:
            sound_send_close();
            break;
        default:
            LOG(10, ("process_pcm_message: unknown id %d", id));
            break;
    }
    return 0;
}

/*****************************************************************************/

/* data in from sound_server_sink */

static int DEFAULT_CC
sound_sndsrvr_sink_data_in(struct trans *trans)
{
    struct stream *s;
    int id;
    int size;
    int error;

    if (trans == 0)
        return 0;

    if (trans != g_audio_c_trans_out)
        return 1;

    s = trans_get_in_s(trans);
    in_uint32_le(s, id);
    in_uint32_le(s, size);

    if ((id & ~3) || (size > 128 * 1024 + 8) || (size < 8))
    {
        LOG(0, ("sound_sndsrvr_sink_data_in: bad message id %d size %d", id, size));
        return 1;
    }

    LOG(10, ("sound_sndsrvr_sink_data_in: good message id %d size %d", id, size));

    error = trans_force_read(trans, size - 8);

    if (error == 0)
    {
        /* here, the entire message block is read in, process it */
        error = process_pcm_message(id, size - 8, s);
    }

    return error;
}

/*****************************************************************************/

/* incoming connection on unix domain socket - sound_server_sink -> xrdp */

static int DEFAULT_CC
sound_sndsrvr_sink_conn_in(struct trans *trans, struct trans *new_trans)
{
    LOG(0, ("sound_sndsrvr_sink_conn_in:"));

    if (trans == 0)
        return 1;

    if (trans != g_audio_l_trans_out)
        return 1;

    if (g_audio_c_trans_out != 0) /* if already set, error */
        return 1;

    if (new_trans == 0)
        return 1;

    g_audio_c_trans_out = new_trans;
    g_audio_c_trans_out->trans_data_in = sound_sndsrvr_sink_data_in;
    g_audio_c_trans_out->header_size = 8;
    trans_delete(g_audio_l_trans_out);
    g_audio_l_trans_out = 0;

    return 0;
}

/*****************************************************************************/

/* incoming connection on unix domain socket - sound_server_source -> xrdp */

static int DEFAULT_CC
sound_sndsrvr_source_conn_in(struct trans *trans, struct trans *new_trans)
{
    LOG(0, ("sound_sndsrvr_source_conn_in: client connected"));

    if (trans == 0)
        return 1;

    if (trans != g_audio_l_trans_in)
        return 1;

    if (g_audio_c_trans_in != 0) /* if already set, error */
        return 1;

    if (new_trans == 0)
        return 1;

    g_audio_c_trans_in = new_trans;
    g_audio_c_trans_in->trans_data_in = sound_sndsrvr_source_data_in;
    g_audio_c_trans_in->header_size = 8;
    trans_delete(g_audio_l_trans_in);
    g_audio_l_trans_in = 0;

    return 0;
}

/*****************************************************************************/
int APP_CC
sound_init(void)
{
    char port[256];

    LOG(0, ("sound_init:"));

    g_memset(g_sent_flag, 0, sizeof(g_sent_flag));

#ifdef XRDP_LOAD_PULSE_MODULES
    if (load_pulse_modules())
        LOG(0, ("Audio and microphone redirection will not work!"));
#endif

    /* init sound output */
    sound_send_server_output_formats();

    g_audio_l_trans_out = trans_create(TRANS_MODE_UNIX, 128 * 1024, 8192);
    g_audio_l_trans_out->is_term = g_is_term;
    g_snprintf(port, 255, CHANSRV_PORT_OUT_STR, g_display_num);
    g_audio_l_trans_out->trans_conn_in = sound_sndsrvr_sink_conn_in;

    if (trans_listen(g_audio_l_trans_out, port) != 0)
        LOG(0, ("sound_init: trans_listen failed"));

    /* init sound input */
    sound_send_server_input_formats();

    g_audio_l_trans_in = trans_create(TRANS_MODE_UNIX, 128 * 1024, 8192);
    g_audio_l_trans_in->is_term = g_is_term;
    g_snprintf(port, 255, CHANSRV_PORT_IN_STR, g_display_num);
    g_audio_l_trans_in->trans_conn_in = sound_sndsrvr_source_conn_in;

    if (trans_listen(g_audio_l_trans_in, port) != 0)
        LOG(0, ("sound_init: trans_listen failed"));

    /* save data from sound_server_source */
    fifo_init(&in_fifo, 100);

#if defined(XRDP_SIMPLESOUND)

    /* start thread to read raw audio data from pulseaudio device */
    tc_thread_create(read_raw_audio_data, 0);

#endif

    return 0;
}

/*****************************************************************************/
int APP_CC
sound_deinit(void)
{
    if (g_audio_l_trans_out != 0)
    {
        trans_delete(g_audio_l_trans_out);
        g_audio_l_trans_out = 0;
    }

    if (g_audio_c_trans_out != 0)
    {
        trans_delete(g_audio_c_trans_out);
        g_audio_c_trans_out = 0;
    }

    if (g_audio_l_trans_in != 0)
    {
        trans_delete(g_audio_l_trans_in);
        g_audio_l_trans_in = 0;
    }

    if (g_audio_c_trans_in != 0)
    {
        trans_delete(g_audio_c_trans_in);
        g_audio_c_trans_in = 0;
    }

    fifo_deinit(&in_fifo);

#ifdef XRDP_LOAD_PULSE_MODULES
    system("pulseaudio --kill");
#endif

    return 0;
}

/*****************************************************************************/

/* data in from client ( client -> xrdp -> chansrv ) */

int APP_CC
sound_data_in(struct stream *s, int chan_id, int chan_flags, int length,
              int total_length)
{
    int code;
    int size;

    in_uint8(s, code);
    in_uint8s(s, 1);
    in_uint16_le(s, size);

    switch (code)
    {
        case SNDC_WAVECONFIRM:
            sound_process_wave_confirm(s, size);
            break;

        case SNDC_TRAINING:
            sound_process_training(s, size);
            break;

        case SNDC_FORMATS:
            sound_process_output_formats(s, size);
            break;

        case SNDC_REC_NEGOTIATE:
            sound_process_input_formats(s, size);
            break;

        case SNDC_REC_DATA:
            sound_process_input_data(s, size);
            break;

        default:
            LOG(10, ("sound_data_in: unknown code %d size %d", code, size));
            break;
    }

    return 0;
}

/*****************************************************************************/
int APP_CC
sound_get_wait_objs(tbus *objs, int *count, int *timeout)
{
    int lcount;

    lcount = *count;

    if (g_audio_l_trans_out != 0)
    {
        objs[lcount] = g_audio_l_trans_out->sck;
        lcount++;
    }

    if (g_audio_c_trans_out != 0)
    {
        objs[lcount] = g_audio_c_trans_out->sck;
        lcount++;
    }

    if (g_audio_l_trans_in != 0)
    {
        objs[lcount] = g_audio_l_trans_in->sck;
        lcount++;
    }

    if (g_audio_c_trans_in != 0)
    {
        objs[lcount] = g_audio_c_trans_in->sck;
        lcount++;
    }

    *count = lcount;
    return 0;
}

/*****************************************************************************/
int APP_CC
sound_check_wait_objs(void)
{
    if (g_audio_l_trans_out != 0)
    {
        trans_check_wait_objs(g_audio_l_trans_out);
    }

    if (g_audio_c_trans_out != 0)
    {
        trans_check_wait_objs(g_audio_c_trans_out);
    }

    if (g_audio_l_trans_in != 0)
    {
        trans_check_wait_objs(g_audio_l_trans_in);
    }

    if (g_audio_c_trans_in != 0)
    {
        trans_check_wait_objs(g_audio_c_trans_in);
    }

    return 0;
}

/**
 * Load xrdp pulseaudio sink and source modules
 *
 * @return 0 on success, -1 on failure
 *****************************************************************************/

#ifdef XRDP_LOAD_PULSE_MODULES

static int APP_CC
load_pulse_modules()
{
    struct sockaddr_un sa;

    pid_t pid;
    char* cli;
    int   fd;
    int   i;
    int   rv;
    char  buf[1024];

    /* is pulse audio daemon running? */
    if (pa_pid_file_check_running(&pid, "pulseaudio") < 0)
    {
        LOG(0, ("load_pulse_modules: No PulseAudio daemon running, "
                "or not running as session daemon"));
    }

    /* get name of unix domain socket used by pulseaudio for CLI */
    if ((cli = (char *) pa_runtime_path("cli")) == NULL)
    {
        LOG(0, ("load_pulse_modules: Error getting PulesAudio runtime path"));
        return -1;
    }

    /* open a socket */
    if ((fd = socket(PF_LOCAL, SOCK_STREAM, 0)) < 0)
    {
        pa_xfree(cli);
        LOG(0, ("load_pulse_modules: Socket open error"));
        return -1;
    }

    /* set it up */
    memset(&sa, 0, sizeof(struct sockaddr_un));
    sa.sun_family = AF_UNIX;
    pa_strlcpy(sa.sun_path, cli, sizeof(sa.sun_path));
    pa_xfree(cli);

    for (i = 0; i < 20; i++)
    {
        if (pa_pid_file_kill(SIGUSR2, NULL, "pulseaudio") < 0)
            LOG(0, ("load_pulse_modules: Failed to kill PulseAudio daemon"));

        if ((rv = connect(fd, (struct sockaddr*) &sa, sizeof(sa))) < 0 &&
            (errno != ECONNREFUSED && errno != ENOENT))
        {
            LOG(0, ("load_pulse_modules: connect() failed with error: %s",
                    strerror(errno)));
            return -1;
        }

        if (rv >= 0)
            break;

        pa_msleep(300);
    }

    if (i >= 20)
    {
        LOG(0, ("load_pulse_modules: Daemon not responding"));
        return -1;
    }

    LOG(0, ("load_pulse_modules: connected to pulseaudio daemon"));

    /* read back PulseAudio sign on message */
    memset(buf, 0, 1024);
    recv(fd, buf, 1024, 0);

    /* send cmd to load source module */
    memset(buf, 0, 1024);
    sprintf(buf, "load-module module-xrdp-source\n");
    send(fd, buf, strlen(buf), 0);

    /* read back response */
    memset(buf, 0, 1024);
    recv(fd, buf, 1024, 0);
    if (strcasestr(buf, "Module load failed") != 0)
    {
        LOG(0, ("load_pulse_modules: Error loading module-xrdp-source"));
    }
    else
    {
        LOG(0, ("load_pulse_modules: Loaded module-xrdp-source"));

        /* success, set it as the default source */
        memset(buf, 0, 1024);
        sprintf(buf, "set-default-source xrdp-source\n");
        send(fd, buf, strlen(buf), 0);

        memset(buf, 0, 1024);
        recv(fd, buf, 1024, 0);

        if (strcasestr(buf, "does not exist") != 0)
        {
            LOG(0, ("load_pulse_modules: Error setting default source"));
        }
        else
        {
            LOG(0, ("load_pulse_modules: set default source"));
        }
    }

    /* send cmd to load sink module */
    memset(buf, 0, 1024);
    sprintf(buf, "load-module module-xrdp-sink\n");
    send(fd, buf, strlen(buf), 0);

    /* read back response */
    memset(buf, 0, 1024);
    recv(fd, buf, 1024, 0);
    if (strcasestr(buf, "Module load failed") != 0)
    {
        LOG(0, ("load_pulse_modules: Error loading module-xrdp-sink"));
    }
    else
    {
        LOG(0, ("load_pulse_modules: Loaded module-xrdp-sink"));

        /* success, set it as the default sink */
        memset(buf, 0, 1024);
        sprintf(buf, "set-default-sink xrdp-sink\n");
        send(fd, buf, strlen(buf), 0);

        memset(buf, 0, 1024);
        recv(fd, buf, 1024, 0);

        if (strcasestr(buf, "does not exist") != 0)
        {
            LOG(0, ("load_pulse_modules: Error setting default sink"));
        }
        else
        {
            LOG(0, ("load_pulse_modules: set default sink"));
        }
    }

    close(fd);
    return 0;
}
#endif

/******************************************************************************
 **                                                                          **
 **                       Microphone releated code                           **
 **                                                                          **
 ******************************************************************************/

/**
 *
 *****************************************************************************/

static int APP_CC
sound_send_server_input_formats(void)
{
    struct stream* s;
    int    bytes;
    int    index;
    char*  size_ptr;

    make_stream(s);
    init_stream(s, 8182);
    out_uint16_le(s, SNDC_REC_NEGOTIATE);
    size_ptr = s->p;
    out_uint16_le(s, 0);                   /* size, set later */
    out_uint32_le(s, 0);                   /* unused */
    out_uint32_le(s, 0);                   /* unused */
    out_uint16_le(s, SND_NUM_INP_FORMATS); /* wNumberOfFormats */
    out_uint16_le(s, 2);                   /* wVersion */

    /*
        wFormatTag      2 byte offset 0
        nChannels       2 byte offset 2
        nSamplesPerSec  4 byte offset 4
        nAvgBytesPerSec 4 byte offset 8
        nBlockAlign     2 byte offset 12
        wBitsPerSample  2 byte offset 14
        cbSize          2 byte offset 16
        data            variable offset 18
    */

    for (index = 0; index < SND_NUM_INP_FORMATS; index++)
    {
        out_uint16_le(s, g_wave_inp_formats[index]->wFormatTag);
        out_uint16_le(s, g_wave_inp_formats[index]->nChannels);
        out_uint32_le(s, g_wave_inp_formats[index]->nSamplesPerSec);
        out_uint32_le(s, g_wave_inp_formats[index]->nAvgBytesPerSec);
        out_uint16_le(s, g_wave_inp_formats[index]->nBlockAlign);
        out_uint16_le(s, g_wave_inp_formats[index]->wBitsPerSample);
        bytes = g_wave_inp_formats[index]->cbSize;
        out_uint16_le(s, bytes);
        if (bytes > 0)
        {
            out_uint8p(s, g_wave_inp_formats[index]->data, bytes);
        }
    }

    s_mark_end(s);
    bytes = (int)((s->end - s->data) - 4);
    size_ptr[0] = bytes;
    size_ptr[1] = bytes >> 8;
    bytes = (int)(s->end - s->data);
    send_channel_data(g_rdpsnd_chan_id, s->data, bytes);
    free_stream(s);
    return 0;
}

/**
 *
 *****************************************************************************/

static int APP_CC
sound_process_input_format(int aindex, int wFormatTag, int nChannels,
                           int nSamplesPerSec, int nAvgBytesPerSec,
                           int nBlockAlign, int wBitsPerSample,
                           int cbSize, char *data)
{
    LOG(10, ("sound_process_input_format:"));
    LOG(10, ("      wFormatTag      %d", wFormatTag));
    LOG(10, ("      nChannels       %d", nChannels));
    LOG(10, ("      nSamplesPerSec  %d", nSamplesPerSec));
    LOG(10, ("      nAvgBytesPerSec %d", nAvgBytesPerSec));
    LOG(10, ("      nBlockAlign     %d", nBlockAlign));
    LOG(10, ("      wBitsPerSample  %d", wBitsPerSample));
    LOG(10, ("      cbSize          %d", cbSize));

#if 0
    /* select CD quality audio */
    if (wFormatTag == g_pcm_inp_44100.wFormatTag &&
        nChannels == g_pcm_inp_44100.nChannels &&
        nSamplesPerSec == g_pcm_inp_44100.nSamplesPerSec &&
        nAvgBytesPerSec == g_pcm_inp_44100.nAvgBytesPerSec &&
        nBlockAlign == g_pcm_inp_44100.nBlockAlign &&
        wBitsPerSample == g_pcm_inp_44100.wBitsPerSample)
    {
        g_client_input_format_index = aindex;
        g_server_input_format_index = 0;
    }
#else
    /* select half of CD quality audio */
    if (wFormatTag == g_pcm_inp_22050.wFormatTag &&
        nChannels == g_pcm_inp_22050.nChannels &&
        nSamplesPerSec == g_pcm_inp_22050.nSamplesPerSec &&
        nAvgBytesPerSec == g_pcm_inp_22050.nAvgBytesPerSec &&
        nBlockAlign == g_pcm_inp_22050.nBlockAlign &&
        wBitsPerSample == g_pcm_inp_22050.wBitsPerSample)
    {
        g_client_input_format_index = aindex;
        g_server_input_format_index = 0;
    }
#endif

    return 0;
}

/**
 *
 *****************************************************************************/

static int APP_CC
sound_process_input_formats(struct stream *s, int size)
{
    int num_formats;
    int index;
    int wFormatTag;
    int nChannels;
    int nSamplesPerSec;
    int nAvgBytesPerSec;
    int nBlockAlign;
    int wBitsPerSample;
    int cbSize;
    char *data;

    LOG(10, ("sound_process_input_formats: size=%d", size));

    in_uint8s(s, 8); /* skip 8 bytes */
    in_uint16_le(s, num_formats);
    in_uint8s(s, 2); /* skip version */

    if (num_formats > 0)
    {
        for (index = 0; index < num_formats; index++)
        {
            in_uint16_le(s, wFormatTag);
            in_uint16_le(s, nChannels);
            in_uint32_le(s, nSamplesPerSec);
            in_uint32_le(s, nAvgBytesPerSec);
            in_uint16_le(s, nBlockAlign);
            in_uint16_le(s, wBitsPerSample);
            in_uint16_le(s, cbSize);
            in_uint8p(s, data, cbSize);
            sound_process_input_format(index, wFormatTag, nChannels, nSamplesPerSec,
                                       nAvgBytesPerSec, nBlockAlign, wBitsPerSample,
                                       cbSize, data);
        }
    }

    return 0;
}

/**
 *
 *****************************************************************************/

static int APP_CC
sound_input_start_recording()
{
    struct stream* s;

    /* if there is any data in FIFO, discard it */
    while ((s = (struct stream *) fifo_remove(&in_fifo)) != NULL)
        xstream_free(s);

    xstream_new(s, 1024);

    /*
     * command format
     *
     * 02 bytes command SNDC_REC_START
     * 02 bytes length
     * 02 bytes data format received earlier
     */

    out_uint16_le(s, SNDC_REC_START);
    out_uint16_le(s, 2);
    out_uint16_le(s, g_client_input_format_index);

    s_mark_end(s);
    send_channel_data(g_rdpsnd_chan_id, s->data, 6);
    xstream_free(s);

    return 0;
}

/**
 *
 *****************************************************************************/

static int APP_CC
sound_input_stop_recording()
{
    struct stream* s;

    xstream_new(s, 1024);

    /*
     * command format
     *
     * 02 bytes command SNDC_REC_STOP
     * 02 bytes length (zero)
     */

    out_uint16_le(s, SNDC_REC_STOP);
    out_uint16_le(s, 0);

    s_mark_end(s);
    send_channel_data(g_rdpsnd_chan_id, s->data, 4);
    xstream_free(s);

    return 0;
}

/**
 * Process data: xrdp <- client
 *****************************************************************************/

static unsigned char data = 0;

static int APP_CC
sound_process_input_data(struct stream *s, int bytes)
{
    struct stream *ls;

    xstream_new(ls, bytes);
    memcpy(ls->data, s->p, bytes);
    ls->p += bytes;
    s_mark_end(ls);

    fifo_insert(&in_fifo, (void *) ls);

    return 0;
}

/**
 * Got a command from sound_server_source
 *****************************************************************************/

static int DEFAULT_CC
sound_sndsrvr_source_data_in(struct trans *trans)
{
    struct stream *ts = NULL;
    struct stream *s  = NULL;

    tui16    bytes_req   = 0;
    int      bytes_read  = 0;
    int      cmd;
    int      i;

    if (trans == 0)
        return 0;

    if (trans != g_audio_c_trans_in)
        return 1;

    ts = trans_get_in_s(trans);
    trans_force_read(trans, 3);

    ts->p = ts->data + 8;
    in_uint8(ts, cmd);
    in_uint16_le(ts, bytes_req);

    if (bytes_req != 0)
        xstream_new(s, bytes_req + 2);

    if (cmd == PA_CMD_SEND_DATA)
    {
        /* set real len later */
        out_uint16_le(s, 0);

        while (bytes_read < bytes_req)
        {
            if (g_stream_inp == NULL)
                g_stream_inp = (struct stream *) fifo_remove(&in_fifo);

            if (g_stream_inp == NULL)
            {
                /* no more data, send what we have */
                break;
            }
            else
            {
                if (g_bytes_in_stream == 0)
                    g_bytes_in_stream = g_stream_inp->size;

                i = bytes_req - bytes_read;

                if (i < g_bytes_in_stream)
                {
                    xstream_copyin(s, &g_stream_inp->data[g_stream_inp->size - g_bytes_in_stream], i);
                    bytes_read += i;
                    g_bytes_in_stream -= i;
                }
                else
                {
                    xstream_copyin(s, &g_stream_inp->data[g_stream_inp->size - g_bytes_in_stream], g_bytes_in_stream);
                    bytes_read += g_bytes_in_stream;
                    g_bytes_in_stream = 0;
                    xstream_free(g_stream_inp);
                    g_stream_inp = NULL;
                }
            }
        }

        if (bytes_read)
        {
            s->data[0] = (char) (bytes_read & 0xff);
            s->data[1] = (char) ((bytes_read >> 8) & 0xff);
        }

        s_mark_end(s);

        trans_force_write_s(trans, s);
        xstream_free(s);
    }
    else if (cmd == PA_CMD_START_REC)
    {
        sound_input_start_recording();
    }
    else if (cmd == PA_CMD_STOP_REC)
    {
        sound_input_stop_recording();
    }

    return 0;
}

/*****************************************************************************/

#if defined(XRDP_SIMPLESOUND)

#define AUDIO_BUF_SIZE 2048

static int DEFAULT_CC
sttrans_data_in(struct trans *self)
{
    LOG(0, ("sttrans_data_in:\n"));
    return 0;
}

/**
 * read raw audio data from pulseaudio device and write it
 * to a unix domain socket on which trans server is listening
 */

static void *DEFAULT_CC
read_raw_audio_data(void *arg)
{
    pa_sample_spec samp_spec;
    pa_simple *simple = NULL;
    uint32_t bytes_read;
    char *cptr;
    int i;
    int error;
    struct trans *strans;
    char path[256];
    struct stream *outs;

    strans = trans_create(TRANS_MODE_UNIX, 8192, 8192);

    if (strans == 0)
    {
        LOG(0, ("read_raw_audio_data: trans_create failed\n"));
        return 0;
    }

    strans->trans_data_in = sttrans_data_in;
    g_snprintf(path, 255, CHANSRV_PORT_OUT_STR, g_display_num);

    if (trans_connect(strans, "", path, 100) != 0)
    {
        LOG(0, ("read_raw_audio_data: trans_connect failed\n"));
        trans_delete(strans);
        return 0;
    }

    /* setup audio format */
    samp_spec.format = PA_SAMPLE_S16LE;

#if HQ_AUDIO
    samp_spec.rate = 44100;
    samp_spec.channels = 2;
#else
    samp_spec.rate = 22050;
    samp_spec.channels = 2;
#endif

    /* if we are root, then for first 8 seconds connection to pulseaudo server
       fails; if we are non-root, then connection succeeds on first attempt;
       for now we have changed code to be non-root, but this may change in the
       future - so pretend we are root and try connecting to pulseaudio server
       for upto one minute */
    for (i = 0; i < 60; i++)
    {
        simple = pa_simple_new(NULL, "xrdp", PA_STREAM_RECORD, NULL,
                               "record", &samp_spec, NULL, NULL, &error);

        if (simple)
        {
            /* connected to pulseaudio server */
            LOG(0, ("read_raw_audio_data: connected to pulseaudio server\n"));
            break;
        }

        LOG(0, ("read_raw_audio_data: ERROR creating PulseAudio async interface\n"));
        LOG(0, ("read_raw_audio_data: %s\n", pa_strerror(error)));
        g_sleep(1000);
    }

    if (i == 60)
    {
        /* failed to connect to audio server */
        trans_delete(strans);
        return NULL;
    }

    /* insert header just once */
    outs = trans_get_out_s(strans, 8192);
    out_uint32_le(outs, 0);
    out_uint32_le(outs, AUDIO_BUF_SIZE + 8);
    cptr = outs->p;
    out_uint8s(outs, AUDIO_BUF_SIZE);
    s_mark_end(outs);

    while (1)
    {
        /* read a block of raw audio data... */
        g_memset(cptr, 0, 4);
        bytes_read = pa_simple_read(simple, cptr, AUDIO_BUF_SIZE, &error);

        if (bytes_read < 0)
        {
            LOG(0, ("read_raw_audio_data: ERROR reading from pulseaudio stream\n"));
            LOG(0, ("read_raw_audio_data: %s\n", pa_strerror(error)));
            break;
        }

        /* bug workaround:
           even when there is no audio data, pulseaudio is returning without
           errors but the data itself is zero; we use this zero data to
           determine that there is no audio data present */
        if (*cptr == 0 && *(cptr + 1) == 0 && *(cptr + 2) == 0 && *(cptr + 3) == 0)
        {
            g_sleep(10);
            continue;
        }

        if (trans_force_write_s(strans, outs) != 0)
        {
            LOG(0, ("read_raw_audio_data: ERROR writing audio data to server\n"));
            break;
        }
    }

    pa_simple_free(simple);
    trans_delete(strans);
    return NULL;
}

#endif
