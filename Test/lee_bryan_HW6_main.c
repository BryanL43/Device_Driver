/**************************************************************
* Name:: Bryan Lee
* GitHub-Name:: BryanL43
*
* File:: lee_bryan_HW6_main.c
*
* Description:: Application that executes the device driver.
*
**************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#define FILE_LOCATION "/dev/Vigenere"
#define BUFFER_SIZE 512
#define MODE_ENCRYPT 'e'
#define MODE_DECRYPT 'd'

int main(int argc, char* argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Invalid arguments count\n");
        return -1;
    }

    // Parse arguments
    const char cipherMode = argv[1][0];
    const char* text = argv[2];
    const char* key = argv[3];

    // Validate cipher mode
    if (cipherMode != MODE_ENCRYPT && cipherMode != MODE_DECRYPT) {
        fprintf(stderr, "Invalid cipher mode: expected 'e' or 'd', recieved '%c'\n", cipherMode);
        return -1;
    }

    int fd = open(FILE_LOCATION, O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "Device failed to open!\n");
        return -1;
    }

    // Write the message to the device driver
    if (write(fd, text, strlen(text)) == -1) {
        fprintf(stderr, "Error: failed to write message to device!\n");
        close(fd);
        return -1;
    }

    // Executes the encryption/decryption operation
    if (ioctl(fd, cipherMode, key) == -1) {
        fprintf(stderr, "Error: Ioctl failed to executed!\n");
        close(fd);
        return -1;
    }

    // Instantiate the response buffer
    char* response = malloc(BUFFER_SIZE);
    if (response == NULL) {
        fprintf(stderr, "Failed to instantiate response buffer!\n");
        close(fd);
        return -1;
    }

    // Reads the device driver's response
    if (read(fd, response, strlen(text)) < 0) {
        fprintf(stderr, "Failed to read response!\n");
        return -1;
    }
    printf("Result: %s\n", response);

    free(response);
    close(fd);
    return 0;
}