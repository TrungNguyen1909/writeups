CC = clang
.PHONY: run clean

pillow_exploit: exploit.c shelld.defs shelld_client.defs
	mig shelld.defs
	mig shelld_client.defs
	gcc exploit.c shelldUser.c shelld_clientUser.c -o exploit

clean:
	rm -f exploit shelld.h shelldServer.c shelldUser.c shelld_client.h shelld_clientServer.c shelld_clientUser.c

run: pillow_exploit
	sandbox-exec -f sandbox.sb -DBINARY=$(shell pwd)/exploit ./exploit
