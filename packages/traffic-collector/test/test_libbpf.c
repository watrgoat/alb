// test_libbpf.c
#include <libbpf.h>
#include <stdio.h>

int main()
{
	printf("libbpf version: %d.%d\n", libbpf_major_version(),
	       libbpf_minor_version());
	return 0;
}
