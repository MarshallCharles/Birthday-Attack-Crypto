all: verif attack generate_key

tczero.o: tczero.c tczero.h
	gcc -c tczero.c

hashmap.o: hashmap.c hashmap.h cbc.h
	gcc -c hashmap.c

cbc.o: cbc.c cbc.h
	gcc -c cbc.c

verif.o: verif.c
	gcc -c verif.c

verif: tczero.o cbc.o verif.o
	gcc -o verif tczero.o cbc.o verif.o

attack.o: attack.c
	gcc -c attack.c

attack: tczero.o cbc.o hashmap.o attack.o
	gcc -o attack tczero.o cbc.o hashmap.o attack.o

generate_key.o: generate_key.c
	gcc -c generate_key.c

generate_key: tczero.o cbc.o generate_key.o
	gcc -o generate_key tczero.o cbc.o generate_key.o

clean:
	rm *.o verif attack generate_key 2> /dev/null
