/**************************************************************
* Name:: Bryan Lee
* GitHub-Name:: BryanL43
*
* File:: Vigenere.c
*
* Description:: Simple device driver that encrypts or decrypts
*               a message using Vigenère cipher.
*
**************************************************************/

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/vmalloc.h>
#include <linux/sched.h>

#define MY_MAJOR 415
#define MY_MINOR 0
#define DEVICE_NAME "Vigenere"

MODULE_AUTHOR("Bryan Lee");
MODULE_DESCRIPTION("A simple device driver that encrypts/decrypts text using Vigenère cipher");
MODULE_LICENSE("GPL");

static char* resolveKey(char* key, int textLen);
static char encryptChar(char c, char key);
static char decryptChar(char c, char key);
static int encrypt(char* text, char* key);
static int decrypt(char* text, char* key);

#define BUFFER_SIZE 512
#define MODE_ENCRYPT 'e'
#define MODE_DECRYPT 'd'

int major, minor;

struct cdev my_cdev;
int actual_rx_size = 0;

// Structure to store data for encryption/decryption
typedef struct myds {
    char* text; // The message to be encrypted/decrypted
    char* key;  // The key to encrypt/decrypt the message
    int cipher; // Encrypt: 1; Decrypt: 0;
} myds;

/**
 * Initializes our data structure and opens the file descriptor.
 * 
 * @param inode pointer to the inode structure representing the device file.
 * @param fs pointer to the file structure associated with the opened device file.
 * @return 0 on success, or -1 on failure.
*/
static int myOpen(struct inode* inode, struct file* fs) {
    // Instantiate the device driver's data structure
    struct myds* ds = vmalloc(sizeof(struct myds));
    if (!ds) {
        printk(KERN_ERR "Can not vmalloc, File not opened.\n");
        return -1;
    }

    // Instantiate the message buffer
    ds->text = vmalloc(BUFFER_SIZE);
    if (ds->text == NULL) {
        printk(KERN_ERR "Failed to vmalloc text buffer.\n");
        vfree(ds);
        return -1;
    }

    // Instantiate the key buffer
    ds->key = vmalloc(BUFFER_SIZE);
    if (ds->key == NULL) {
        printk(KERN_ERR "Failed to vmalloc text buffer.\n");
        vfree(ds->text);
        vfree(ds);
        return -1;
    }

    ds->cipher = 0;
    fs->private_data = ds;

    return 0;
}

/**
 * Writes the user's message to our data structure.
 * 
 * @param fs pointer to the file structure/file descriptor.
 * @param buf pointer to the user's buffer containing data to be written.
 * @param hsize the number of bytes to write from the user's buffer.
 * @param off pointer to the file's offset.
 * @return the number of bytes written or -1 on failure.
*/
static ssize_t myWrite(struct file* fs, const char __user* buf, size_t hsize, loff_t* off) {
    struct myds* ds = (struct myds*) fs->private_data;

    // Prevents invalid number of bytes to write
    if (hsize <= 0) {
        return hsize;
    }

    // Ensure that we do not write more than BUFFER_SIZE
    if (hsize > BUFFER_SIZE) {
        hsize = BUFFER_SIZE;
    }

    // Copies the user's message to our data structure
    int failedToCopy = copy_from_user(ds->text, buf, hsize);
    if (failedToCopy > 0) {
        printk(KERN_ERR "copy_from_user failed, %d bytes were not copied.\n", failedToCopy);
        return -1;
    }
    ds->text[hsize] = '\0';

    return hsize;
}

/**
 * Reads the encrypted/decrypted message from our data structure back to user.
 * 
 * @param fs pointer to the file structure/file descriptor.
 * @param buf pointer to the user's buffer to copy into.
 * @param hsize the number of bytes to read from our data structure's buffer.
 * @param off pointer to the file's offset.
 * @return the number of bytes read or -1 on failure.
*/
static ssize_t myRead(struct file* fs, char __user* buf, size_t hsize, loff_t* off) {
    struct myds* ds = (struct myds*) fs->private_data;

    // Encrypt/Decrypt job
    switch (ds->cipher) {
        case 1: // Encrypt
            if (encrypt(ds->text, ds->key) == -1) {
                return -1;
            }
            break;
        case 0: // Decrypt
            if (decrypt(ds->text, ds->key) == -1) {
                return -1;
            }
            break;
        default:
            printk(KERN_ERR "Fatal: Invalid cipher operation during read!\n");
            return -1;
    }
    
    ssize_t dataSize = strlen(ds->text);

    // Prevents invalid number of bytes to read
    if (hsize <= 0) {
        return hsize;
    }

    // Ensure read does not exceeds buffer size
    if (hsize > BUFFER_SIZE) {
        hsize = BUFFER_SIZE;
    }

    // Ensure the read size does not exceed the available data (EOF)
    if (*off >= dataSize) {
        return 0;
    }

    // Shifts read location to the beginning of unread data
    if (*off + hsize > dataSize) {
        hsize = dataSize - *off;
    }
    
    // Copies our message to user's buffer
    int failedToCopy = copy_to_user(buf, ds->text + *off, hsize);
    if (failedToCopy > 0) {
        printk(KERN_ERR "copy_to_user failed, %d bytes were not copied.\n", failedToCopy);
        return -1;
    }

    *off += hsize;

    return hsize;
}

// Free our data structure and close the file decriptor.
static int myClose(struct inode* inode, struct file* fs) {
    struct myds* ds = (struct myds*) fs->private_data;
    vfree(ds->text);
    vfree(ds->key);
    vfree(ds);

    return 0;
}

/**
 * Repeats the key to the length of the message to be encrypted/decrypted.
 * i.e. "This is a test message" with "key" : "key" -> "keykeykeykeykeykeykeyk"
 * 
 * @param key the key to be resolved.
 * @param textLen the length of the message to be encrypted/decrypted.
 * @return the resolved key or NULL on failure.
*/
static char* resolveKey(char* key, int textLen) {
    // Instantiate resolved key buffer
    char* resolvedKey = vmalloc(textLen + 1);
    if (resolvedKey == NULL) {
        return NULL;
    }
    
    // Iterate through the length of the message to create a repeated key
    // that matches the length of the message.
    int j = 0;
    for (int i = 0; i < textLen; i++) {
        if (j == strlen(key)) {
            j = 0;
        }
        resolvedKey[i] = key[j];
        j++;
    }
    resolvedKey[textLen] = '\0';
    
    return resolvedKey;
}

/**
 * Encrypts a singular alphabetical character using Vigenère cipher.
 * 
 * @param c the character to be encrypted.
 * @param key the key character that determines the shift amount.
 * @return the encrypted character.
*/
static char encryptChar(char c, char key) {
    if (c >= 'a' && c <= 'z') { // case: lowercase letters

        // If c is lowercase, convert key to lowercase if it's not already
        if (key >= 'A' && key <= 'Z') {
            key = key + ('a' - 'A');
        }

        return ((c - 'a' + (key - 'a')) % 26) + 'a';
    } else if (c >= 'A' && c <= 'Z') { // case: uppercase letters

        // If c is uppercase, convert key to uppercase if it's not already
        if (key >= 'a' && key <= 'z') {
            key = key - ('a' - 'A');
        }

        return ((c - 'A' + (key - 'A')) % 26) + 'A';
    } else {
        return c;
    }
}

/**
 * Decrypts a singular alphabetical character using Vigenère cipher.
 * 
 * @param c the character to be decrypted.
 * @param key the key character that determines the shift amount.
 * @return the decrypted character.
*/
static char decryptChar(char c, char key) {
    if (c >= 'a' && c <= 'z') { // case: lowercase letter

        // If c is lowercase, convert key to lowercase if it's not already
        if (key >= 'A' && key <= 'Z') {
            key = key + ('a' - 'A');
        }

        return ((c - 'a' - (key - 'a') + 26) % 26) + 'a';
    } else if (c >= 'A' && c <= 'Z') { // case: uppercase letter
        
        // If c is uppercase, convert key to uppercase if it's not already
        if (key >= 'a' && key <= 'z') {
            key = key - ('a' - 'A');
        }

        return ((c - 'A' - (key - 'A') + 26) % 26) + 'A';
    } else {
        return c;
    }
}

/**
 * Encrypts the message with its associated key.
 * 
 * @param text the message to be encrypted.
 * @param key the key used to encrypt the message.
 * @return 0 on success, or -1 on failure.
*/
static int encrypt(char* text, char* key) {
    int textLen = strlen(text);
    
    // Repeats the key to ensure that key length matches the message,
    // which is necessary for Vigenère cipher.
    char* resolvedKey = resolveKey(key, textLen);
    if (resolvedKey == NULL) {
        return -1;
    }

    // Iterate through the message, encrypting one letter at a time
    // and excluding any non-alphabetical characters.
    int j = 0;
    for (int i = 0; i < textLen; i++) {
        char c = text[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
            text[i] = encryptChar(c, resolvedKey[j]);
            j++;
        } else {
            text[i] = c;
        }
    }
    text[textLen] = '\0';
    
    vfree(resolvedKey);
    return 0;
}

/**
 * Decrypts the message with its associated key.
 * 
 * @param text the message to be decrypted.
 * @param key the key used to decrypt the message.
 * @return 0 on success, or -1 on failure.
*/
static int decrypt(char* text, char* key) {
    int textLen = strlen(text);
    
    // Repeats the key to ensure that key length matches the message,
    // which is necessary for Vigenère cipher.
    char* resolvedKey = resolveKey(key, textLen);
    if (resolvedKey == NULL) {
        printk(KERN_INFO "Failed to allocate memory to resolvedKey.\n");
        return -1;
    }
    
    // Iterate through the message, decrypting one letter at a time
    // and excluding any non-alphabetical characters.
    int j = 0;
    for (int i = 0; i < textLen; i++) {
        char c = text[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
            text[i] = decryptChar(c, resolvedKey[j]);
            j++;
        } else {
            text[i] = c;
        }
    }
    text[textLen] = '\0';
    
    vfree(resolvedKey);
    return 0;
}

/**
 * Sets the cipher job based on user specified command.
 * 
 * @param fs pointer to the file structure/file descriptor.
 * @param command the IOCTL command that specifies the operation: encrypt/decrypt.
 * @param data pointer to the key used for encrypting/decrypting.
 * @return 0 on success, or -1 on failure.
*/
static long myIoCtl(struct file* fs, unsigned int command, unsigned long data) {
    struct myds* ds = (struct myds*) fs->private_data;

    // Copies the user supplied key to our data structure
    if (copy_from_user(ds->key, (char __user*) data, sizeof(ds->key)) > 0) {
        printk(KERN_ERR "Failed to write key.\n");
        return -1;
    }

    // Set the operation to encryption or decryption based on given command
    switch(command) {
        case MODE_ENCRYPT:
            ds->cipher = 1;
            break;
        case MODE_DECRYPT:
            ds->cipher = 0;
            break;
        default:
            printk(KERN_ERR "Invalid cipher mode, expected 'e' or 'd', got %c\n", command);
            return -1;
    }

    return 0;
}

// File operations structure
struct file_operations fops = {
    .open = myOpen,
    .release = myClose,
    .write = myWrite,
    .read = myRead,
    .unlocked_ioctl = myIoCtl,
    .owner = THIS_MODULE,
};

// Created a device node in /dev, returns error if not made
int init_module(void) {
    int result, registers;
    dev_t devno = MKDEV(MY_MAJOR, MY_MINOR);

    registers = register_chrdev_region(devno, 1, DEVICE_NAME);
    printk(KERN_INFO "Register chardev succeeded 1: %d\n", registers);
    cdev_init(&my_cdev, &fops);
    my_cdev.owner = THIS_MODULE;

    result = cdev_add(&my_cdev, devno, 1);
    printk(KERN_INFO "Dev Add chardev succeeded 2: %d\n", result);
    printk(KERN_INFO "Welcome - Vigenère driver is loaded.\n");
    if (result < 0) {
        printk(KERN_ERR "Register chardev failed: %d\n", result);
    }

    return result;
}

// Unregistering and removing device from kernel
void cleanup_module(void) {
    dev_t devno = MKDEV(MY_MAJOR, MY_MINOR);
    unregister_chrdev_region(devno, 1);
    cdev_del(&my_cdev);
    printk(KERN_INFO "Goodbye from Vigenère driver!\n");
}