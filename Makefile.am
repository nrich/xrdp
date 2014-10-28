EXTRA_DIST = bootstrap COPYING design.txt faq-compile.txt faq-general.txt file-loc.txt install.txt prog_std.txt readme.txt

if XRDP_NEUTRINORDP
NEUTRINORDPDIR = neutrinordp
else
NEUTRINORDPDIR =
endif

if XRDP_XRDPVR
XRDPVRDIR = xrdpvr
else
XRDPVRDIR =
endif

if XRDP_NXVNC
XRDPNXVNCDIR = nx-vnc
else
XRDPNXVNCDIR = 
endif

if XRDP_NXXUP
XRDPNXXUPDIR = nx-xup
else
XRDPNXXUPDIR = 
endif


SUBDIRS = \
  common \
  vnc \
  rdp \
  $(XRDPNXVNCDIR) \
  $(XRDPNXXUPDIR) \
  xup \
  mc \
  $(NEUTRINORDPDIR) \
  libxrdp \
  xrdp \
  sesman \
  keygen \
  docs \
  instfiles \
  genkeymap \
  xrdpapi \
  $(XRDPVRDIR)
