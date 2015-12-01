all: test_srp test_srp11

all_tests: test test

test_srp: test_srp.c srp.c
	gcc -o test_srp test_srp.c srp.c -lcrypto

test_srp11: test_srp11.c srp.c srp11.c
	# gcc -ggdb3 -DDEBUG -DDEBUG_SIGNUPDATE -I /usr/local/src/SoftHSMv2/src/lib/cryptoki_compat/ -Wl,-rpath=/usr/local/src/SoftHSMv2/src/lib/.libs -o test_srp11 test_srp11.c srp.c srp11.c /usr/local/src/SoftHSMv2/src/lib/.libs/libsofthsm2.so -lcrypto
	gcc -ggdb3 -DDEBUG -DDEBUG_SIGNUPDATE -I /usr/local/src/SoftHSMv2/src/lib/cryptoki_compat/ -L /usr/local/lib/softhsm -Wl,-rpath=/usr/local/lib/softhsm -o test_srp11 test_srp11.c srp.c srp11.c -lsofthsm2 -lcrypto

test: test_srp
	./test_srp

test11: test_srp11
	./test_srp11

clean:
	rm -rf test_srp test_srp11

anew:	clean all
