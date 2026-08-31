/*
 * libaff4-c.h — the C ABI for reading AFF4 containers.
 *
 * Implemented by aff4tools. The declarations match c-aff4's header of the same
 * name, so a consumer written against either links against this one unchanged:
 * The Sleuth Kit built with HAVE_LIBAFF4 calls exactly these functions, and
 * Arsenal Image Mounter loads the resulting library as libaff4.dll.
 *
 * All thirteen entry points c-aff4 exports from its C ABI are implemented
 * here, so a C consumer of either library links against this one. Note the
 * limit of that claim: c-aff4's shared library ALSO exports its C++ classes
 * (AFF4Map, ZipFile, DataStore and the rest). A C++ consumer using those is
 * NOT served by this library. Call AFF4_version() to tell the two apart at
 * runtime -- it returns "aff4tools <version>" here and
 * "libaff4 version <version>" there.
 *
 * One function is added beyond c-aff4's set: AFF4_free_property(), which
 * releases the buffers the property accessors return. It exists because
 * c-aff4's "call free()" contract is unsafe across a heap boundary. Adding an
 * export breaks nothing -- a consumer that never calls it is unaffected --
 * and c-aff4 has not been updated since March 2023, so the ABI it defines is
 * a fixed point rather than a moving one.
 *
 * Everything here reads. There is no write, truncate, or create entry point.
 *
 * Split sets are invisible: AFF4_open on any part of a numbered set discovers
 * its siblings and presents the whole image. A caller cannot tell, and does not
 * need to know, whether a container is one file or twenty.
 */

#ifndef LIBAFF4_C_H_
#define LIBAFF4_C_H_

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The implementation's version string. Static; do not free. */
const char* AFF4_version(void);

typedef enum {
    AFF4_LOG_LEVEL_TRACE = 0,
    AFF4_LOG_LEVEL_DEBUG = 1,
    AFF4_LOG_LEVEL_INFO = 2,
    AFF4_LOG_LEVEL_WARNING = 3,
    AFF4_LOG_LEVEL_ERROR = 4,
    AFF4_LOG_LEVEL_CRITICAL = 5,
    AFF4_LOG_LEVEL_OFF = 6
} AFF4_LOG_LEVEL;

/*
 * A linked list of messages. Every list produced by this API MUST be freed with
 * AFF4_free_messages().
 *
 * This is where error detail survives the language boundary: a malformed
 * container reports what was wrong and where, rather than collapsing to an
 * errno.
 */
typedef struct AFF4_Message {
    AFF4_LOG_LEVEL level;
    char* message;
    struct AFF4_Message* next;
} AFF4_Message;

void AFF4_free_messages(AFF4_Message* msg);

/*
 * Accepted and ignored: this implementation reports through the msg
 * out-parameters and never logs on its own.
 */
void AFF4_set_verbosity(AFF4_LOG_LEVEL level);

/* Accepted and ignored: this implementation caches no handles. */
void AFF4_set_handle_cache_size(unsigned int n);
void AFF4_clear_handle_cache(void);

typedef struct AFF4_Handle AFF4_Handle;

/*
 * Open `filename` and access the first aff4:DiskImage in the container.
 *
 * Returns NULL on failure, with *msg populated when msg is non-NULL. An AFF4-L
 * logical container is detected and reported as such rather than as a missing
 * image.
 */
AFF4_Handle* AFF4_open(const char* filename, AFF4_Message** msg);

/* The size in bytes of the image the handle was opened on. */
uint64_t AFF4_object_size(AFF4_Handle* handle, AFF4_Message** msg);

/*
 * Read `length` bytes at `offset` into `buffer`.
 *
 * Returns the number of bytes placed in the buffer, 0 at or past the end of the
 * image, or -1 on error with *msg populated. Short reads occur only at the end
 * of the image.
 *
 * Safe to call concurrently on one handle: reads are serialized internally.
 */
ssize_t AFF4_read(AFF4_Handle* handle, uint64_t offset, void* buffer,
                  size_t length, AFF4_Message** msg);

/* Close a handle. Returns 0, or -1 if the handle is NULL. */
int AFF4_close(AFF4_Handle* handle, AFF4_Message** msg);

/*
 * Property accessors.
 *
 * Each reads a property of the object the handle was opened on -- as in
 * c-aff4, which queries handle->urn rather than an arbitrary subject. The
 * property may be given as a full IRI ("http://aff4.org/Schema#size") or as a
 * bare local name ("size"); both are accepted.
 *
 * All return 0 on success, or non-zero with *msg populated. A property that is
 * absent, or whose value will not convert to the requested type, is an error
 * rather than a guess.
 */
int AFF4_get_boolean_property(AFF4_Handle* handle, const char* property,
                              int* result, AFF4_Message** msg);
int AFF4_get_integer_property(AFF4_Handle* handle, const char* property,
                              int64_t* result, AFF4_Message** msg);

/*
 * On success *result is a NUL-terminated string the caller owns and must
 * release with AFF4_free_property().
 */
int AFF4_get_string_property(AFF4_Handle* handle, const char* property,
                             char** result, AFF4_Message** msg);

/*
 * Result of binary data. `data` is owned by the caller and must be released
 * with AFF4_free_property(); `length` is the byte count. Both are cleared on
 * failure, so a caller that releases unconditionally is safe.
 */
typedef struct {
    void* data;
    size_t length;
} AFF4_Binary_Result;

/*
 * A binary property, decoded from the hex form the Turtle stores it in.
 *
 * Digests are the case this exists for: aff4:hash is written as hex, and a
 * caller wanting the 32 raw bytes of a SHA-256 asks here rather than through
 * the string accessor. An odd-length or non-hex value is refused, matching
 * c-aff4's RDFBytes::UnSerializeFromString.
 */
int AFF4_get_binary_property(AFF4_Handle* handle, const char* property,
                             AFF4_Binary_Result* result, AFF4_Message** msg);

/*
 * Release a buffer from AFF4_get_string_property or
 * AFF4_get_binary_property. Passing NULL is a no-op.
 *
 * THIS IS AN ADDITION TO c-aff4's ABI, not part of it.
 *
 * c-aff4 tells the caller to use free(). That is correct only where the
 * library and the consumer share one heap. On Windows they often do not --
 * each C runtime has its own -- so a buffer allocated inside libaff4.dll and
 * released by a consumer linked against a different CRT is undefined
 * behavior: heap corruption rather than a clean failure. Freeing in the
 * module that allocated removes the question entirely.
 *
 * Existing code written against c-aff4 that calls free() directly continues
 * to work anywhere a single heap is shared, which is every Unix. Nothing is
 * broken by this addition; prefer it in new code, and require it on Windows.
 */
void AFF4_free_property(void* ptr);

#ifdef __cplusplus
}
#endif

#endif /* LIBAFF4_C_H_ */
