all: download

download: download.o
	gcc -o download download.o

download.o: download.c
	gcc -o download.o download.c -c -Wall

clean:
	rm -rf *.o *~ download