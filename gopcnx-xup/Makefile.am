EXTRA_DIST = gopcnx-xup.h

AM_CFLAGS = \
  -DXRDP_CFG_PATH=\"${sysconfdir}/xrdp\" \
  -DXRDP_SBIN_PATH=\"${sbindir}\" \
  -DXRDP_SHARE_PATH=\"${datadir}/xrdp\" \
  -DXRDP_PID_PATH=\"${localstatedir}/run\"

INCLUDES = \
  -I$(top_srcdir)/common

lib_LTLIBRARIES = \
  libgopcnx_xup.la

libgopcnx_xup_la_SOURCES = gopcnx-xup.c

libgopcnx_xup_la_LIBADD = \
  $(top_builddir)/common/libcommon.la \
  -ljansson
