
// Originally from
// http://sourceforge.net/apps/phpbb/samygo/viewtopic.php?f=18&t=1810&p=16193&hilit=decrypt#p16193
// gcc -g -o decrypt_fw_samsung decrypt_fw_samsung.c -lcrypto

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <openssl/aes.h>
#include <zlib.h>


#ifndef MODEL
#define MODEL 0x5500
#endif
#define C5500 0x5500
#define C6900 0x6900

typedef struct {
    unsigned char                   v1[4];
    unsigned char                   v2[4];
    unsigned char                   v3[4];
    unsigned char                   v4[4];
} sam_flash_struct_t1;


typedef struct {
    char                            type[6];
    char                            endian[4];
    char                            valuex[2];
    char                            string[32];
    char                            model1[8];
    char                            model2[32];
#if MODEL == C6900
    char                            model3[31];
#elif MODEL == C5500
    char                            model3[33];
#endif
    char                            model4[5];
    unsigned char                   size[4];
} sam_flash_struct_t;

static char *partname[] = {
    NULL,                   //      Commands for flushing
    "exe.img",              //  1   ??? stl.restore ???
    "Image",                //  2   fsrrestore /dev/bml0/{5|7}  Image
    "rootfs.img",           //  3   fsrrestore /dev/bml0/{6|8}  rootfs.img
    "appdata.img",          //  4   ??? stl.restore ???
    "loader",               //  5   ??? BR/DVD/CD disc drive firmware ???
    "onboot",               //  6   fsrbootwriter /dev/bml0/c   onboot.bin
    "boot_image.raw",       //  7   fsrrestore /dev/bml0/20     boot_image.raw
    "bootsound",            //  8   fsrrestore /dev/bml0/22     BootSound
    "cmac.bin",             //  9   fsrrestore /dev/bml0/{9|10} cmac.bin
    "key.bin",              // 10   fsrrestore /dev/bml0/11     key.bin
};

sam_flash_struct_t             *flash_file;
sam_flash_struct_t1            *flash_subfiles;

unsigned int swap_endian(unsigned char *val)
{
    return (val[0] << 24) | (val[1] << 16) | (val[2] << 8) | (val[3]);
}


void aes_decrypt_128(const unsigned char *in, unsigned char *out, unsigned char *key)
{
    AES_KEY                         akey;

    AES_set_decrypt_key(key, 128, &akey);
    AES_decrypt(in, out, &akey);
}

void print128(unsigned char *bytes)
{
    int                             j;

    for (j = 0; j < 16; j++) {
        printf("%02x", bytes[j]);
        //printf(" ");
    }
}

int main(int argc, char *argv[])
{
    unsigned int                    filesize, i, n, b;
    FILE                           *inputfp, *outputfp;
    char                            buffer[1024];
    unsigned char                  *inbuf, *outbuf;
    unsigned char                   iv_init[0x10] = { 0, };
    unsigned char                   mkey[] =
#if MODEL == C6900
        // BD-C6900
        { 0xEA, 0xEA, 0x51, 0x2D, 0xA9, 0x1F, 0x87, 0xE1, 0xC4, 0x15, 0x4C, 0x3E, 0xDB, 0x7A, 0xAD, 0xB8 };
#elif MODEL == C5500
        // BD-C5500
        { 0x48, 0x77, 0x81, 0x5A, 0x17, 0x51, 0x14, 0x80, 0xF9, 0xD1, 0x5B, 0xDF, 0xE3, 0x0C, 0x21, 0x63 };
#endif

    int                             decrypt_point = 0;
    int                             subfile_count = 0;
    unsigned char                  *buff;
    unsigned char                  *p_buf;

    memset(buffer, 0, sizeof(buffer));

    for (b = 1; b < argc; b++) {
        unsigned char                   iv[16];
        char            *cptr, *pptr = NULL;
        //int            rc;

        if (!(inputfp = fopen(argv[b], "rb"))) {
            perror(argv[b]);
            return 3;
        }
        //outputfp = fopen((char *)buffer, "wb");
        fseek(inputfp, 0, SEEK_END);
        filesize = ftell(inputfp);
        fseek(inputfp, 0, SEEK_SET);

        memset(buffer, 0, 1024);

        // create directory
        if (!(cptr = strrchr(argv[b], '/')))
            cptr = argv[b];
        else
            cptr++;
        strcpy(buffer, cptr);
        cptr = buffer;
        while ((cptr = strstr(cptr, ".RUF"))) {
            pptr = cptr;
            cptr += 4;
        }
        if (!pptr)
            pptr = buffer + strlen(buffer);
        strcpy(pptr, ".dir");
        if (mkdir(buffer, 0755) && errno != EEXIST) {
            fprintf(stderr, "Can not create output directory ");
            perror(buffer);
            return 1;
        }
        printf("Output directory: %s\n", buffer);

        inbuf = (unsigned char *)malloc(filesize);
        outbuf = (unsigned char *)malloc(filesize + 0x40);
        memset(outbuf, 0, filesize + 0x40);

        // Reading and decryption
        printf("Decrypting firmware file (%d) ... ", filesize);
        fflush(stdout);
        fread(inbuf, filesize, 1, inputfp);
        flash_file = (sam_flash_struct_t *) inbuf;
        decrypt_point = swap_endian(&flash_file->size[0]);
        subfile_count = inbuf[0xc1];
        //~ printf("decrypt_point = %x\n", decrypt_point);

        memcpy(outbuf, inbuf, 0x800);   // header
        memcpy(iv, iv_init, 16);
        for (i = 0x800; i < decrypt_point + 0x800; i += 16) {
            unsigned char                  *out = outbuf + i;
            //~ if ((i % (1024*1024)) == 0)
                //~ printf("i = %x\n", i);

            aes_decrypt_128(inbuf + i, outbuf + i, mkey);
            for (n = 0; n < 16; n++)
                out[n] ^= iv[n];
            memcpy(iv, inbuf + i, 16);
        }
        memcpy(outbuf + decrypt_point + 0x800, inbuf + decrypt_point + 0x800, filesize - decrypt_point - 0x800);
        //fwrite(outbuf, filesize, 1, outputfp);
        //fclose(outputfp);
        fclose(inputfp);
        printf("Done\n");

        buff = outbuf + 0x800;
        p_buf = outbuf + 0x120;
        for (i = 0; i < subfile_count;) {
            unsigned int                  f, s;

            flash_subfiles = (sam_flash_struct_t1 *) p_buf;
            f = swap_endian(flash_subfiles->v1);
            s = swap_endian(flash_subfiles->v2);
            if (s > filesize) {
                fprintf(stderr, "%s: Wrong header format. Aborting\n", argv[b]);
                return 2;
            }
            if (f) {
                char   file_out[1100];
                char   *pname = "unknown";
                if (f > 0 && f < sizeof(partname)/sizeof(char *))
                    pname = partname[f];
                sprintf(file_out, "%s/part_%02d.%s", buffer, f, pname);
                printf("Writing %-60s ... ", file_out);
                fflush(stdout);
                if (!(outputfp = fopen(file_out, "wb"))) {
                    fprintf(stderr, "Can not create output file ");
                    perror(file_out);
                    return 4;
                }
                fwrite(buff, s, 1, outputfp);
                fclose(outputfp);
                sync();
                printf("OK\n");
                buff += s;
                i++;
            }

            p_buf += 0x40;
        }
        free(inbuf);
        free(outbuf);
    }
    return 0;
}
