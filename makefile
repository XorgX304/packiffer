CC=gcc

packiffer: packiffer.c
*****$(CC) -pthread -o packiffer packiffer.c -lpcap
