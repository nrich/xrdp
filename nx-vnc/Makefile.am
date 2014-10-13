EXTRA_DIST = nx-vnc.h

AM_CFLAGS = \
  -DXRDP_CFG_PATH=\"${sysconfdir}/xrdp\" \
  -DXRDP_SBIN_PATH=\"${sbindir}\" \
  -DXRDP_SHARE_PATH=\"${datadir}/xrdp\" \
  -DXRDP_PID_PATH=\"${localstatedir}/run\"

INCLUDES = \
  -I$(top_srcdir)/common

lib_LTLIBRARIES = \
  libnx-vnc.la

libnx-vnc_la_SOURCES = nx-vnc.c

libnx-vnc_la_LIBADD = \
  $(top_builddir)/common/libcommon.la
