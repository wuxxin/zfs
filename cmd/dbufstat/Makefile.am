dist_bin_SCRIPTS = dbufstat

#
# The dbufstat script is compatible with both Python 2.6 and 3.4.
# As such the python 3 shebang can be replaced at install time when
# targeting a python 2 system.  This allows us to maintain a single
# version of the source.
#
if USING_PYTHON_2
install-exec-hook:
	sed --in-place 's|^#!/usr/bin/python3|#!/usr/bin/python2|' \
	    $(DESTDIR)$(bindir)/dbufstat
endif
