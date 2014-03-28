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
 * cache
 */

#include "xrdp.h"
#include "log.h"

#define LLOG_LEVEL 1
#define LLOGLN(_level, _args) \
  do \
  { \
    if (_level < LLOG_LEVEL) \
    { \
        g_write("xrdp:xrdp_cache [%10.10u]: ", g_time3()); \
        g_writeln _args ; \
    } \
  } \
  while (0)

/*****************************************************************************/
struct xrdp_cache *APP_CC
xrdp_cache_create(struct xrdp_wm *owner,
                  struct xrdp_session *session,
                  struct xrdp_client_info *client_info)
{
    struct xrdp_cache *self;

    self = (struct xrdp_cache *)g_malloc(sizeof(struct xrdp_cache), 1);
    self->wm = owner;
    self->session = session;
    self->use_bitmap_comp = client_info->use_bitmap_comp;

    self->cache1_entries = MIN(XRDP_MAX_BITMAP_CACHE_IDX,
                               client_info->cache1_entries);
    self->cache1_entries = MAX(self->cache1_entries, 0);
    self->cache1_size = client_info->cache1_size;

    self->cache2_entries = MIN(XRDP_MAX_BITMAP_CACHE_IDX,
                               client_info->cache2_entries);
    self->cache2_entries = MAX(self->cache2_entries, 0);
    self->cache2_size = client_info->cache2_size;

    self->cache3_entries = MIN(XRDP_MAX_BITMAP_CACHE_IDX,
                               client_info->cache3_entries);
    self->cache3_entries = MAX(self->cache3_entries, 0);
    self->cache3_size = client_info->cache3_size;

    self->bitmap_cache_persist_enable = client_info->bitmap_cache_persist_enable;
    self->bitmap_cache_version = client_info->bitmap_cache_version;
    self->pointer_cache_entries = client_info->pointer_cache_entries;
    self->xrdp_os_del_list = list_create();
    LLOGLN(10, ("xrdp_cache_create: 0 %d 1 %d 2 %d",
                self->cache1_entries, self->cache2_entries, self->cache3_entries));
    return self;
}

/*****************************************************************************/
void APP_CC
xrdp_cache_delete(struct xrdp_cache *self)
{
    int i;
    int j;

    if (self == 0)
    {
        return;
    }

    /* free all the cached bitmaps */
    for (i = 0; i < XRDP_MAX_BITMAP_CACHE_ID; i++)
    {
        for (j = 0; j < XRDP_MAX_BITMAP_CACHE_IDX; j++)
        {
            xrdp_bitmap_delete(self->bitmap_items[i][j].bitmap);
        }
    }

    /* free all the cached font items */
    for (i = 0; i < 12; i++)
    {
        for (j = 0; j < 256; j++)
        {
            g_free(self->char_items[i][j].font_item.data);
        }
    }

    /* free all the off screen bitmaps */
    for (i = 0; i < 2000; i++)
    {
        xrdp_bitmap_delete(self->os_bitmap_items[i].bitmap);
    }

    list_delete(self->xrdp_os_del_list);

    g_free(self);
}

/*****************************************************************************/
int APP_CC
xrdp_cache_reset(struct xrdp_cache *self,
                 struct xrdp_client_info *client_info)
{
    struct xrdp_wm *wm;
    struct xrdp_session *session;
    int i;
    int j;

    /* free all the cached bitmaps */
    for (i = 0; i < XRDP_MAX_BITMAP_CACHE_ID; i++)
    {
        for (j = 0; j < XRDP_MAX_BITMAP_CACHE_IDX; j++)
        {
            xrdp_bitmap_delete(self->bitmap_items[i][j].bitmap);
        }
    }

    /* free all the cached font items */
    for (i = 0; i < 12; i++)
    {
        for (j = 0; j < 256; j++)
        {
            g_free(self->char_items[i][j].font_item.data);
        }
    }

    /* save these */
    wm = self->wm;
    session = self->session;
    /* set whole struct to zero */
    g_memset(self, 0, sizeof(struct xrdp_cache));
    /* set some stuff back */
    self->wm = wm;
    self->session = session;
    self->use_bitmap_comp = client_info->use_bitmap_comp;
    self->cache1_entries = client_info->cache1_entries;
    self->cache1_size = client_info->cache1_size;
    self->cache2_entries = client_info->cache2_entries;
    self->cache2_size = client_info->cache2_size;
    self->cache3_entries = client_info->cache3_entries;
    self->cache3_size = client_info->cache3_size;
    self->bitmap_cache_persist_enable = client_info->bitmap_cache_persist_enable;
    self->bitmap_cache_version = client_info->bitmap_cache_version;
    self->pointer_cache_entries = client_info->pointer_cache_entries;
    return 0;
}

#define COMPARE_WITH_CRC(_b1, _b2) \
 ((_b1 != 0) && (_b2 != 0) && (_b1->crc == _b2->crc) && \
  (_b1->bpp == _b2->bpp) && \
  (_b1->width == _b2->width) && (_b1->height == _b2->height))

/*****************************************************************************/
/* returns cache id */
int APP_CC
xrdp_cache_add_bitmap(struct xrdp_cache *self, struct xrdp_bitmap *bitmap,
                      int hints)
{
    int i = 0;
    int j = 0;
    int oldest = 0;
    int cache_id = 0;
    int cache_idx = 0;
    int bmp_size = 0;
    int e = 0;
    int Bpp = 0;

    e = bitmap->width % 4;

    if (e != 0)
    {
        e = 4 - e;
    }

    Bpp = (bitmap->bpp + 7) / 8;
    bmp_size = (bitmap->width + e) * bitmap->height * Bpp;
    self->bitmap_stamp++;

    /* look for match */
    if (bmp_size <= self->cache1_size)
    {
        i = 0;

        for (j = 0; j < self->cache1_entries; j++)
        {
#ifdef USE_CRC
            if (COMPARE_WITH_CRC(self->bitmap_items[i][j].bitmap, bitmap))
#else
            if (xrdp_bitmap_compare(self->bitmap_items[i][j].bitmap, bitmap))
#endif
            {
                self->bitmap_items[i][j].stamp = self->bitmap_stamp;
                LLOGLN(10, ("found bitmap at %d %d", i, j));
                xrdp_bitmap_delete(bitmap);
                return MAKELONG(j, i);
            }
        }
    }
    else if (bmp_size <= self->cache2_size)
    {
        i = 1;

        for (j = 0; j < self->cache2_entries; j++)
        {
#ifdef USE_CRC
            if (COMPARE_WITH_CRC(self->bitmap_items[i][j].bitmap, bitmap))
#else
            if (xrdp_bitmap_compare(self->bitmap_items[i][j].bitmap, bitmap))
#endif
            {
                self->bitmap_items[i][j].stamp = self->bitmap_stamp;
                LLOGLN(10, ("found bitmap at %d %d", i, j));
                xrdp_bitmap_delete(bitmap);
                return MAKELONG(j, i);
            }
        }
    }
    else if (bmp_size <= self->cache3_size)
    {
        i = 2;

        for (j = 0; j < self->cache3_entries; j++)
        {
#ifdef USE_CRC
            if (COMPARE_WITH_CRC(self->bitmap_items[i][j].bitmap, bitmap))
#else
            if (xrdp_bitmap_compare(self->bitmap_items[i][j].bitmap, bitmap))
#endif
            {
                self->bitmap_items[i][j].stamp = self->bitmap_stamp;
                LLOGLN(10, ("found bitmap at %d %d", i, j));
                xrdp_bitmap_delete(bitmap);
                return MAKELONG(j, i);
            }
        }
    }
    else
    {
        log_message(LOG_LEVEL_ERROR,"error in xrdp_cache_add_bitmap, too big(%d) bpp %d", bmp_size, bitmap->bpp);
    }

    /* look for oldest */
    cache_id = 0;
    cache_idx = 0;
    oldest = 0x7fffffff;

    if (bmp_size <= self->cache1_size)
    {
        i = 0;

        for (j = 0; j < self->cache1_entries; j++)
        {
            if (self->bitmap_items[i][j].stamp < oldest)
            {
                oldest = self->bitmap_items[i][j].stamp;
                cache_id = i;
                cache_idx = j;
            }
        }
    }
    else if (bmp_size <= self->cache2_size)
    {
        i = 1;

        for (j = 0; j < self->cache2_entries; j++)
        {
            if (self->bitmap_items[i][j].stamp < oldest)
            {
                oldest = self->bitmap_items[i][j].stamp;
                cache_id = i;
                cache_idx = j;
            }
        }
    }
    else if (bmp_size <= self->cache3_size)
    {
        i = 2;

        for (j = 0; j < self->cache3_entries; j++)
        {
            if (self->bitmap_items[i][j].stamp < oldest)
            {
                oldest = self->bitmap_items[i][j].stamp;
                cache_id = i;
                cache_idx = j;
            }
        }
    }

    LLOGLN(10, ("adding bitmap at %d %d ptr %p", cache_id, cache_idx,
                self->bitmap_items[cache_id][cache_idx].bitmap));
    /* set, send bitmap and return */
    xrdp_bitmap_delete(self->bitmap_items[cache_id][cache_idx].bitmap);
    self->bitmap_items[cache_id][cache_idx].bitmap = bitmap;
    self->bitmap_items[cache_id][cache_idx].stamp = self->bitmap_stamp;

    if (self->use_bitmap_comp)
    {
        if (self->bitmap_cache_version & 4)
        {
            if (libxrdp_orders_send_bitmap3(self->session, bitmap->width,
                                            bitmap->height, bitmap->bpp,
                                            bitmap->data, cache_id, cache_idx,
                                            hints) == 0)
            {
                return MAKELONG(cache_idx, cache_id);
            }
        }

        if (self->bitmap_cache_version & 2)
        {
            libxrdp_orders_send_bitmap2(self->session, bitmap->width,
                                        bitmap->height, bitmap->bpp,
                                        bitmap->data, cache_id, cache_idx,
                                        hints);
        }
        else if (self->bitmap_cache_version & 1)
        {
            libxrdp_orders_send_bitmap(self->session, bitmap->width,
                                       bitmap->height, bitmap->bpp,
                                       bitmap->data, cache_id, cache_idx);
        }
    }
    else
    {
        if (self->bitmap_cache_version & 2)
        {
            libxrdp_orders_send_raw_bitmap2(self->session, bitmap->width,
                                            bitmap->height, bitmap->bpp,
                                            bitmap->data, cache_id, cache_idx);
        }
        else if (self->bitmap_cache_version & 1)
        {
            libxrdp_orders_send_raw_bitmap(self->session, bitmap->width,
                                           bitmap->height, bitmap->bpp,
                                           bitmap->data, cache_id, cache_idx);
        }
    }

    return MAKELONG(cache_idx, cache_id);
}

/*****************************************************************************/
/* not used */
/* not sure how to use a palette in rdp */
int APP_CC
xrdp_cache_add_palette(struct xrdp_cache *self, int *palette)
{
    int i;
    int oldest;
    int index;

    if (self == 0)
    {
        return 0;
    }

    if (palette == 0)
    {
        return 0;
    }

    if (self->wm->screen->bpp > 8)
    {
        return 0;
    }

    self->palette_stamp++;

    /* look for match */
    for (i = 0; i < 6; i++)
    {
        if (g_memcmp(palette, self->palette_items[i].palette,
                     256 * sizeof(int)) == 0)
        {
            self->palette_items[i].stamp = self->palette_stamp;
            return i;
        }
    }

    /* look for oldest */
    index = 0;
    oldest = 0x7fffffff;

    for (i = 0; i < 6; i++)
    {
        if (self->palette_items[i].stamp < oldest)
        {
            oldest = self->palette_items[i].stamp;
            index = i;
        }
    }

    /* set, send palette and return */
    g_memcpy(self->palette_items[index].palette, palette, 256 * sizeof(int));
    self->palette_items[index].stamp = self->palette_stamp;
    libxrdp_orders_send_palette(self->session, palette, index);
    return index;
}

/*****************************************************************************/
int APP_CC
xrdp_cache_add_char(struct xrdp_cache *self,
                    struct xrdp_font_char *font_item)
{
    int i;
    int j;
    int oldest;
    int f;
    int c;
    int datasize;
    struct xrdp_font_char *fi;

    self->char_stamp++;

    /* look for match */
    for (i = 7; i < 12; i++)
    {
        for (j = 0; j < 250; j++)
        {
            if (xrdp_font_item_compare(&self->char_items[i][j].font_item, font_item))
            {
                self->char_items[i][j].stamp = self->char_stamp;
                DEBUG(("found font at %d %d", i, j));
                return MAKELONG(j, i);
            }
        }
    }

    /* look for oldest */
    f = 0;
    c = 0;
    oldest = 0x7fffffff;

    for (i = 7; i < 12; i++)
    {
        for (j = 0; j < 250; j++)
        {
            if (self->char_items[i][j].stamp < oldest)
            {
                oldest = self->char_items[i][j].stamp;
                f = i;
                c = j;
            }
        }
    }

    DEBUG(("adding char at %d %d", f, c));
    /* set, send char and return */
    fi = &self->char_items[f][c].font_item;
    g_free(fi->data);
    datasize = FONT_DATASIZE(font_item);
    fi->data = (char *)g_malloc(datasize, 1);
    g_memcpy(fi->data, font_item->data, datasize);
    fi->offset = font_item->offset;
    fi->baseline = font_item->baseline;
    fi->width = font_item->width;
    fi->height = font_item->height;
    self->char_items[f][c].stamp = self->char_stamp;
    libxrdp_orders_send_font(self->session, fi, f, c);
    return MAKELONG(c, f);
}

/*****************************************************************************/
/* added the pointer to the cache and send it to client, it also sets the
   client if it finds it
   returns the index in the cache
   does not take ownership of pointer_item */
int APP_CC
xrdp_cache_add_pointer(struct xrdp_cache *self,
                       struct xrdp_pointer_item *pointer_item)
{
    int i;
    int oldest;
    int index;

    if (self == 0)
    {
        return 0;
    }

    self->pointer_stamp++;

    /* look for match */
    for (i = 2; i < self->pointer_cache_entries; i++)
    {
        if (self->pointer_items[i].x == pointer_item->x &&
                self->pointer_items[i].y == pointer_item->y &&
                g_memcmp(self->pointer_items[i].data,
                         pointer_item->data, 32 * 32 * 4) == 0 &&
                g_memcmp(self->pointer_items[i].mask,
                         pointer_item->mask, 32 * 32 / 8) == 0 &&
                self->pointer_items[i].bpp == pointer_item->bpp)
        {
            self->pointer_items[i].stamp = self->pointer_stamp;
            xrdp_wm_set_pointer(self->wm, i);
            self->wm->current_pointer = i;
            DEBUG(("found pointer at %d", i));
            return i;
        }
    }

    /* look for oldest */
    index = 2;
    oldest = 0x7fffffff;

    for (i = 2; i < self->pointer_cache_entries; i++)
    {
        if (self->pointer_items[i].stamp < oldest)
        {
            oldest = self->pointer_items[i].stamp;
            index = i;
        }
    }

    self->pointer_items[index].x = pointer_item->x;
    self->pointer_items[index].y = pointer_item->y;
    g_memcpy(self->pointer_items[index].data,
             pointer_item->data, 32 * 32 * 4);
    g_memcpy(self->pointer_items[index].mask,
             pointer_item->mask, 32 * 32 / 8);
    self->pointer_items[index].stamp = self->pointer_stamp;
    self->pointer_items[index].bpp = pointer_item->bpp;
    xrdp_wm_send_pointer(self->wm, index,
                         self->pointer_items[index].data,
                         self->pointer_items[index].mask,
                         self->pointer_items[index].x,
                         self->pointer_items[index].y,
                         self->pointer_items[index].bpp);
    self->wm->current_pointer = index;
    DEBUG(("adding pointer at %d", index));
    return index;
}

/*****************************************************************************/
/* this does not take owership of pointer_item, it makes a copy */
int APP_CC
xrdp_cache_add_pointer_static(struct xrdp_cache *self,
                              struct xrdp_pointer_item *pointer_item,
                              int index)
{

    if (self == 0)
    {
        return 0;
    }

    self->pointer_items[index].x = pointer_item->x;
    self->pointer_items[index].y = pointer_item->y;
    g_memcpy(self->pointer_items[index].data,
             pointer_item->data, 32 * 32 * 4);
    g_memcpy(self->pointer_items[index].mask,
             pointer_item->mask, 32 * 32 / 8);
    self->pointer_items[index].stamp = self->pointer_stamp;
    self->pointer_items[index].bpp = pointer_item->bpp;
    xrdp_wm_send_pointer(self->wm, index,
                         self->pointer_items[index].data,
                         self->pointer_items[index].mask,
                         self->pointer_items[index].x,
                         self->pointer_items[index].y,
                         self->pointer_items[index].bpp);
    self->wm->current_pointer = index;
    DEBUG(("adding pointer at %d", index));
    return index;
}

/*****************************************************************************/
/* this does not take owership of brush_item_data, it makes a copy */
int APP_CC
xrdp_cache_add_brush(struct xrdp_cache *self,
                     char *brush_item_data)
{
    int i;
    int oldest;
    int index;

    if (self == 0)
    {
        return 0;
    }

    self->brush_stamp++;

    /* look for match */
    for (i = 0; i < 64; i++)
    {
        if (g_memcmp(self->brush_items[i].pattern,
                     brush_item_data, 8) == 0)
        {
            self->brush_items[i].stamp = self->brush_stamp;
            DEBUG(("found brush at %d", i));
            return i;
        }
    }

    /* look for oldest */
    index = 0;
    oldest = 0x7fffffff;

    for (i = 0; i < 64; i++)
    {
        if (self->brush_items[i].stamp < oldest)
        {
            oldest = self->brush_items[i].stamp;
            index = i;
        }
    }

    g_memcpy(self->brush_items[index].pattern,
             brush_item_data, 8);
    self->brush_items[index].stamp = self->brush_stamp;
    libxrdp_orders_send_brush(self->session, 8, 8, 1, 0x81, 8,
                              self->brush_items[index].pattern, index);
    DEBUG(("adding brush at %d", index));
    return index;
}

/*****************************************************************************/
/* returns error */
int APP_CC
xrdp_cache_add_os_bitmap(struct xrdp_cache *self, struct xrdp_bitmap *bitmap,
                         int rdpindex)
{
    struct xrdp_os_bitmap_item *bi;

    if ((rdpindex < 0) || (rdpindex >= 2000))
    {
        return 1;
    }

    bi = self->os_bitmap_items + rdpindex;
    bi->bitmap = bitmap;
    return 0;
}

/*****************************************************************************/
/* returns error */
int APP_CC
xrdp_cache_remove_os_bitmap(struct xrdp_cache *self, int rdpindex)
{
    struct xrdp_os_bitmap_item *bi;
    int index;

    if ((rdpindex < 0) || (rdpindex >= 2000))
    {
        return 1;
    }

    bi = self->os_bitmap_items + rdpindex;

    if (bi->bitmap->tab_stop)
    {
        index = list_index_of(self->xrdp_os_del_list, rdpindex);

        if (index == -1)
        {
            list_add_item(self->xrdp_os_del_list, rdpindex);
        }
    }

    xrdp_bitmap_delete(bi->bitmap);
    g_memset(bi, 0, sizeof(struct xrdp_os_bitmap_item));
    return 0;
}

/*****************************************************************************/
struct xrdp_os_bitmap_item *APP_CC
xrdp_cache_get_os_bitmap(struct xrdp_cache *self, int rdpindex)
{
    struct xrdp_os_bitmap_item *bi;

    if ((rdpindex < 0) || (rdpindex >= 2000))
    {
        return 0;
    }

    bi = self->os_bitmap_items + rdpindex;
    return bi;
}
