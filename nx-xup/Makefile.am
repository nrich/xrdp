EXTRA_DIST = nx-xup.h

AM_CFLAGS = \
  -DXRDP_CFG_PATH=\"${sysconfdir}/xrdp\" \
  -DXRDP_SBIN_PATH=\"${sbindir}\" \
  -DXRDP_SHARE_PATH=\"${datadir}/xrdp\" \
  -DXRDP_PID_PATH=\"${localstatedir}/run\"

INCLUDES = \
  -I$(top_srcdir)/common

lib_LTLIBRARIES = \
  libnx_xup.la

libnx_xup_la_SOURCES = nx-xup.c

libnx_xup_la_LIBADD = \
  $(top_builddir)/common/libcommon.la
  -lssh
