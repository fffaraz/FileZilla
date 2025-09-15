noinst_PROGRAMS = timer_fizzbuzz process nonblocking_process events list https raw_https aio

timer_fizzbuzz_SOURCES = timer_fizzbuzz.cpp

timer_fizzbuzz_CPPFLAGS = $(AM_CPPFLAGS)
timer_fizzbuzz_CPPFLAGS += -I$(top_srcdir)/lib

timer_fizzbuzz_LDFLAGS = $(AM_LDFLAGS)
timer_fizzbuzz_LDFLAGS += -no-install

timer_fizzbuzz_LDADD = ../lib/libfilezilla.la
timer_fizzbuzz_LDADD += $(libdeps)

timer_fizzbuzz_DEPENDENCIES = ../lib/libfilezilla.la


process_SOURCES = process.cpp

process_CPPFLAGS = $(AM_CPPFLAGS)
process_CPPFLAGS += -I$(top_srcdir)/lib

process_LDFLAGS = $(AM_LDFLAGS)
process_LDFLAGS += -no-install

process_LDADD = ../lib/libfilezilla.la
process_LDADD += $(libdeps)

process_DEPENDENCIES = ../lib/libfilezilla.la

nonblocking_process_SOURCES = nonblocking_process.cpp

nonblocking_process_CPPFLAGS = $(AM_CPPFLAGS)
nonblocking_process_CPPFLAGS += -I$(top_srcdir)/lib

nonblocking_process_LDFLAGS = $(AM_LDFLAGS)
nonblocking_process_LDFLAGS += -no-install

nonblocking_process_LDADD = ../lib/libfilezilla.la
nonblocking_process_LDADD += $(libdeps)

nonblocking_process_DEPENDENCIES = ../lib/libfilezilla.la


events_SOURCES = events.cpp

events_CPPFLAGS = $(AM_CPPFLAGS)
events_CPPFLAGS += -I$(top_srcdir)/lib

events_LDFLAGS = $(AM_LDFLAGS)
events_LDFLAGS += -no-install

events_LDADD = ../lib/libfilezilla.la
events_LDADD += $(libdeps)

events_DEPENDENCIES = ../lib/libfilezilla.la


list_SOURCES = list.cpp

list_CPPFLAGS = $(AM_CPPFLAGS)
list_CPPFLAGS += -I$(top_srcdir)/lib

list_LDFLAGS = $(AM_LDFLAGS)
list_LDFLAGS += -no-install

list_LDADD = ../lib/libfilezilla.la
list_LDADD += $(libdeps)

list_DEPENDENCIES = ../lib/libfilezilla.la

https_SOURCES = https.cpp

https_CPPFLAGS = $(AM_CPPFLAGS)
https_CPPFLAGS += -I$(top_srcdir)/lib

https_LDFLAGS = $(AM_LDFLAGS)
https_LDFLAGS += -no-install

https_LDADD = ../lib/libfilezilla.la
https_LDADD += $(libdeps)

https_DEPENDENCIES = ../lib/libfilezilla.la


raw_https_SOURCES = raw_https.cpp

raw_https_CPPFLAGS = $(AM_CPPFLAGS)
raw_https_CPPFLAGS += -I$(top_srcdir)/lib

raw_https_LDFLAGS = $(AM_LDFLAGS)
raw_https_LDFLAGS += -no-install

raw_https_LDADD = ../lib/libfilezilla.la
raw_https_LDADD += $(libdeps)

raw_https_DEPENDENCIES = ../lib/libfilezilla.la


aio_SOURCES = aio.cpp

aio_CPPFLAGS = $(AM_CPPFLAGS)
aio_CPPFLAGS += -I$(top_srcdir)/lib

aio_LDFLAGS = $(AM_LDFLAGS)
aio_LDFLAGS += -no-install

aio_LDADD = ../lib/libfilezilla.la
aio_LDADD += $(libdeps)

aio_DEPENDENCIES = ../lib/libfilezilla.la


if !FZ_WINDOWS
noinst_PROGRAMS += impersonation

impersonation_SOURCES = impersonation.cpp

impersonation_CPPFLAGS = $(AM_CPPFLAGS)
impersonation_CPPFLAGS += -I$(top_srcdir)/lib

impersonation_LDFLAGS = $(AM_LDFLAGS)
impersonation_LDFLAGS += -no-install

impersonation_LDADD = ../lib/libfilezilla.la
impersonation_LDADD += $(libdeps)

impersonation_DEPENDENCIES = ../lib/libfilezilla.la
endif

noinst_PROGRAMS += xml_pp
xml_pp_SOURCES = xml_pp.cpp

xml_pp_CPPFLAGS = $(AM_CPPFLAGS)
xml_pp_CPPFLAGS += -I$(top_srcdir)/lib

xml_pp_LDFLAGS = $(AM_LDFLAGS)
xml_pp_LDFLAGS += -no-install

xml_pp_LDADD = ../lib/libfilezilla.la
xml_pp_LDADD += $(libdeps)

xml_pp_DEPENDENCIES = ../lib/libfilezilla.la


dist_noinst_DATA = \
	examples.txt
