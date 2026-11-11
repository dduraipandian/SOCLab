CFLAGS ?= -O2 -Wall -Wextra -Wno-unused-parameter -fPIC -D_FORTIFY_SOURCE=0

libsensor.so: sensor_hook.c
	$(CC) $(CFLAGS) -shared -o $@ $< -ldl
