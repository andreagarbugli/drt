CC=gcc
CFLAGS="-g -Wall -Wextra"
CFLAGS="$CFLAGS -Wno-unused-variable -Wno-override-init -Wno-type-limits"
LFLAGS="-lpthread -ldl -lm"
INCLUDES="-I../"

$CC $CFLAGS udb.c $INCLUDES $LFLAGS -o udb
