out : test.c
	clang -g -o out test.c -lpthread
run : out
	./out

