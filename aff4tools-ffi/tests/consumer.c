/*
 * Task C5: proof that a C consumer can read an AFF4 through this library.
 *
 * Opens a container, reads it in blocks through AFF4_read, and prints the
 * SHA-256 of what came back. If the ABI is wrong anywhere the digest differs
 * from what aff4tools itself computes, which is what the calling test asserts.
 *
 * Deliberately uses only the published header: no Rust, no bindings, nothing
 * this crate provides beyond the library a consumer would link.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <CommonCrypto/CommonDigest.h>
#include "libaff4-c.h"

static void print_messages(const char* what, AFF4_Message* msg) {
    for (AFF4_Message* m = msg; m; m = m->next) {
        fprintf(stderr, "%s: [%d] %s\n", what, (int)m->level,
                m->message ? m->message : "(null)");
    }
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: consumer <container.aff4>\n");
        return 2;
    }

    AFF4_Message* msg = NULL;
    AFF4_Handle* h = AFF4_open(argv[1], &msg);
    if (!h) {
        print_messages("open", msg);
        AFF4_free_messages(msg);
        return 1;
    }
    AFF4_free_messages(msg);
    msg = NULL;

    uint64_t size = AFF4_object_size(h, &msg);
    AFF4_free_messages(msg);
    msg = NULL;

    /* An integer property the ABI does expose, checked against the size. */
    int64_t via_property = 0;
    if (AFF4_get_integer_property(h, "size", &via_property, &msg) == 0) {
        if ((uint64_t)via_property != size) {
            fprintf(stderr, "size property %lld disagrees with %llu\n",
                    (long long)via_property, (unsigned long long)size);
            AFF4_free_messages(msg);
            AFF4_close(h, NULL);
            return 1;
        }
    }
    AFF4_free_messages(msg);
    msg = NULL;

    CC_SHA256_CTX ctx;
    CC_SHA256_Init(&ctx);

    const size_t BLOCK = 1 << 20;
    unsigned char* buf = malloc(BLOCK);
    if (!buf) { AFF4_close(h, NULL); return 1; }

    uint64_t offset = 0;
    uint64_t total = 0;
    for (;;) {
        ssize_t n = AFF4_read(h, offset, buf, BLOCK, &msg);
        if (n < 0) {
            print_messages("read", msg);
            AFF4_free_messages(msg);
            free(buf);
            AFF4_close(h, NULL);
            return 1;
        }
        AFF4_free_messages(msg);
        msg = NULL;
        if (n == 0) break;
        CC_SHA256_Update(&ctx, buf, (CC_LONG)n);
        offset += (uint64_t)n;
        total += (uint64_t)n;
    }
    free(buf);

    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_Final(digest, &ctx);

    printf("size %llu\n", (unsigned long long)size);
    printf("read %llu\n", (unsigned long long)total);
    printf("sha256 ");
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) printf("%02x", digest[i]);
    printf("\n");

    if (AFF4_close(h, &msg) != 0) {
        print_messages("close", msg);
        AFF4_free_messages(msg);
        return 1;
    }
    AFF4_free_messages(msg);
    return 0;
}
