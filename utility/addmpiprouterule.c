/*
 ============================================================================
 Name        : syscalls.c
 Author      : 
 Version     :
 Copyright   : Your copyright notice
 Description : Hello World in C, Ansi-style
 ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>

//
//#include <sys/syscall.h>
//#include <sys/types.h>
//#include <sys/stat.h>
//#include <sys/wait.h>

int main(int argc, char **argv)
{
	printf("%s,%s,%s,%d,%d,%d,%d\n",argv[0], argv[1], argv[2],
			atoi(argv[3]), atoi(argv[4]), atoi(argv[5]), atoi(argv[6]));

	return syscall(316, argv[1], argv[2],
				atoi(argv[3]), atoi(argv[4]), atoi(argv[5]), atoi(argv[6]));
}
