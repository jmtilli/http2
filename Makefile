.PHONY: all
all: sslsrv sslcli

sslsrv: sslsrv.c
	cc -Wall -Wextra -o sslsrv sslsrv.c -lcrypto -lssl

sslcli: sslcli.c
	cc -Wall -Wextra -o sslcli sslcli.c -lcrypto -lssl

