CC=gcc
CFLAGS="-g -Wall -Wextra"
CFLAGS="$CFLAGS -Wno-unused-variable -Wno-override-init -Wno-type-limits -Wno-unused-function" 
LFLAGS="-lpthread -ldl -lm"

$CC $CFLAGS utcp.c $LFLAGS -o utcp
