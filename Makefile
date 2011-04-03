include $(GOROOT)/src/Make.inc

TARG=github.com/dchest/passwordhash
GOFILES=\
	passwordhash.go

include $(GOROOT)/src/Make.pkg

