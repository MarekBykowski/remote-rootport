check_defined = \
    $(strip $(foreach 1,$1, \
        $(call __check_defined,$1,$(strip $(value 2)))))
__check_defined = \
    $(if $(value $1),, \
      $(error Undefined $1$(if $2, ($2))))
#eg. check if SRC provided from command line
#make SRC=file
#target: depend
#	$(call check_defined, SRC)

CC=gcc
CFLAGS=-g -Wall -I./include -I./include_wa_kernel_headers
PKG=pkg-config --cflags --libs glib-2.0

SRC=remote-rc.c daemon-doe.c
OBJ=$(SRC:.c=.o)
#APP=$(patsubst %.c,%,$(SRC))
APP=remote-rc daemon-doe

#$@ - output file/target
#$< - takes only the first item on the dependencies list
#$^ - takes all the items on the dependencies list

#all: $(APP) secure-copy
all: $(APP)

source_files:
	@echo $(SRC)

secure-copy:
	scp $(APP) qr:/home/root

%.o: %.c
	$(call check_defined, SRC)
	$(CC) -o $@ -c $< $(CFLAGS)

remote-rc: remote-rc.o
	$(CC) -o $@ $^ $(LDFLAGS)

daemon-doe: daemon-doe.o
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	rm -f *.o *.a $(APP)

.PHONY: all clean secure-copy
