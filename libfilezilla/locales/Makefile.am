CLEANFILES = *.po.new *.mo libfilezilla.pot libfilezilla.pot.new libfilezilla.pot~

dist_noinst_DATA = @LIBFILEZILLA_LINGUAS_PO@

install-data-local: install-libfilezilla-catalogs

install-libfilezilla-catalogs: allmo
	for i in @LIBFILEZILLA_LINGUAS@ ; do \
	  $(mkinstalldirs) $(DESTDIR)$(localedir)/$$i/LC_MESSAGES ; \
	  $(INSTALL_DATA) $$i.mo $(DESTDIR)$(localedir)/$$i/LC_MESSAGES/libfilezilla.mo ; \
	done

uninstall-local:
	for i in @LIBFILEZILLA_LINGUAS@ ; do \
	  rm $(DESTDIR)$(localedir)/$$i/LC_MESSAGES/libfilezilla.mo ; \
	done

# ----------------------------------------------------------------------------
# Logic for catalogs updating follows
# Try to not modify catalog files if nothing has changed
# But touch them to make sure the timestamps are correct
# so that the uptodate checks are only made if neccessary.
# ----------------------------------------------------------------------------

# the programs we use
MSGFMT=@msgfmt@ -c --verbose --no-hash
MSGMERGE=@msgmerge@ --no-fuzzy-matching
XGETTEXT=@xgettext@

# common xgettext args: C++ syntax, use the specified macro names as markers
XGETTEXT_ARGS=-C -kfztranslate:1,1t -kfztranslate:1,2,3t -kfztranslate_mark:1,1t -kfztranslate_mark:1,2,3t -kwxPLURAL:1,2 -s -j -c@translator --msgid-bugs-address='https://trac.filezilla-project.org/'

# implicit rules
%.mo: %.po.new
	$(MSGFMT) -o $@ $< || exit 1

# a PO file must be updated from libfilezilla.pot to include new translations
%.po.new: $(srcdir)/%.po libfilezilla.pot
	file=$@; \
	cat $(srcdir)/$${file%.po.new}.po > $@
	if [ ! -f $@ ]; then \
	  exit 1; \
	fi
	$(MSGMERGE) $@ libfilezilla.pot -o $@~ || exit 1
	@mv $@~ $@

# touch file so that timestamp is newer than that of filezilla.pot
	@touch $@;

libfilezilla.pot: $(top_srcdir)/lib/libfilezilla/*.hpp $(top_srcdir)/lib/*.hpp $(top_srcdir)/lib/*.cpp
	@rm -f $@.new
	@touch $@.new

	FILES="`find $(top_srcdir)/lib -name '*.hpp' -o -name '*.cpp'`"; \
	$(XGETTEXT) $(XGETTEXT_ARGS) -o $@.new $$FILES || exit 1

# change charset declaration in template file to UTF-8
	cat $@.new | sed -e "s/^\"Content-Type: .*$$/\"Content-Type: text\\/plain; charset=UTF-8\\\\n\"/" > $@.new~
	@mv $@.new~ $@.new

	if [ -f $@ ]; then \
	  touch $@; \
	  $(MSGMERGE) -U $@ $@.new || exit 1; \
	else \
	  mv $@.new $@; \
	fi;

	@if [ -f $@.pot~ ]; then rm $@~; fi
	@if [ -f $@.new ]; then rm $@.new; fi

allpo: @LIBFILEZILLA_LINGUAS_PO_NEW@

# this target which will not be called automatically will update the .po files
updatepo: @LIBFILEZILLA_LINGUAS_PO_NEW@
	for t in @LIBFILEZILLA_LINGUAS@; do \
          cp $$t.po.new $(srcdir)/$$t.po || exit 1; \
        done

allmo: @LIBFILEZILLA_LINGUAS_MO@

all: allmo

.PHONY: allpo allmo force-update FORCE
