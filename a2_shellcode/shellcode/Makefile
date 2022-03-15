default:
	gcc -c shellcode.s -o shellcode.o
	objdump -M intel -D shellcode.o
	ld shellcode.o -o shellcode

clean:
	rm shellcode.o shellcode

test:
	./shellcode
#for i in $(objdump -d shellcode | grep "^ " | cut -f2); do echo -n '\x'$i; done; echo
