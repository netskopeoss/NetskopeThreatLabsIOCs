#include<stdio.h>
#include<Windows.h>

/*
Copyright 2022 Netskope, Inc.
Written by Gustavo Palazolo
Description: This is a simple C++ that creates the same Mutex found in Night Sky ransomware samples, used to test if
             the ransomware was really skipping the encryption process in case the object was already created.
 */

int main() {

    // Mutex found in NightSky ransomware samples
    LPCSTR mutexName = "tset123155465463213";

    if (!OpenMutexA(MUTEX_ALL_ACCESS, true, mutexName)) {

        printf("\n[+] Creating Mutex related to NightSky ransomware\n");
        HANDLE hNSMutex = CreateMutexA(NULL, false, mutexName);
        if (hNSMutex == NULL) {
            printf("[-] Failed to create the mutex\n");
            exit(EXIT_FAILURE);
        }
        printf("[+] Mutex \"tset123155465463213\" created, sleeping for 5 minutes\n");
        Sleep(300000);
        printf("[+] Done");
        exit(EXIT_SUCCESS);
    }

    printf("[+] Mutex is already created\n");
    exit(EXIT_SUCCESS);
}
