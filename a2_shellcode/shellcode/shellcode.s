
_start:
	jmp load_string

code:
	pop	%rsi
	xor	%rax,%rax
	mov	$0x1,%al
	mov	%rax,%rdi
	mov	%rax,%rdx
	add	$0x22,%rdx
	syscall
	
	xor	%rax,%rax
	add	$60,%rax
	xor	%rdi,%rdi
	syscall

load_string:
	call code
	.string "Hello World"
	

