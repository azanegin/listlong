/*
 * directory listing printer
 *
 * AZ - 18.01.2023
 *
 * this program should copy functionality of 'ls' by GNU project
 * but only the 'long listing' part ('ls -l' command)
 * it should work under recent Linux distros
 * Written as a part of a job application test.
 *
 * Long listing should print stuff like this:
 * $ ls -l
 * -rw-------  1 user  group  1630 Nov 18  2017 filename
 * drwxr-xr-x  2 user2  group2  4096 Jul 20  2018  bin
 * lrwxr-xr-x  2 user  group  8 Jul 20  2018  file -> filename
 *
 * That is, with:
 * permissions, hard-link count, owner-user, owner-group, bytesize, mtime, name.
 * User and group should be resolved to symbolic name, if it is possible.
 * https://www.gnu.org/software/coreutils/manual/html_node/What-information-is-listed.html
 *
 * Due to intentionally not supporting '-a' option, we should not print
 * any file whose name starts with a dot ('.').
 *
 * I18n, unicode, multi-byte encodings, colored output, controlling terminal
 * magic, and other fancy stuff are not supported.
 *
 * I would prefer to use some string library, but that would be not-my-code.
 *
 * Sorting by default in ls is charcode-based, so we go that route.
 * https://www.gnu.org/software/coreutils/manual/html_node/Sorting-the-output.html
 *
 *
 * */
#include <stdio.h>
#include <dirent.h>
#include <stdint.h>
#include <errno.h>
#include <stdbool.h>
#include <stdarg.h>
#include <assert.h>
#include <string.h>
#include <sys/stat.h>


static size_t LIMIT_STRLEN = 4096;
static char TIME_FMT_STR[] = "%b %e  %Y";

enum filetype_t
{
    FTYPE_UNKNOWN,
    FTYPE_FIFO,
    FTYPE_CHARDEV,
    FTYPE_DIR,
    FTYPE_BLOCK,
    FTYPE_REGULAR,
    FTYPE_SYMLINK,
    FTYPE_SOCK,
    FTYPE_MAX
};

static inline int
output(char const * format, ...)
{
    int retval = 0;
    va_list args;
    va_start(args, format);
    retval = vfprintf(stdout,  format, args);
    fprintf(stdout, "\n");
    va_end(args);
    return retval;
}

#define DEBUG 1

#if defined(DEBUG)
/* would prefer func, but want __line__ to work without backtrace */
#define log_debug(format, ...) fprintf(stderr, "[%s]: " format "\n", __func__, ##__VA_ARGS__)
#else // not defined(DEBUG)
#define log_debug()
#endif // defined(DEBUG)

static inline void
log_at_libc_err(char const * format, ...)
{
    va_list args;

    va_start(args, format);

    fprintf(stderr, "[%s]: ", strerror(errno));
    vfprintf(stderr,  format, args );

    va_end(args);
}

static inline size_t
extract_name_size_from_dirent(struct dirent * src)
{
#if defined(_DIRENT_HAVE_D_NAMLEN)
    static_assert(sizeof(src->d_namelen) <= sizeof(size_t));
    return (size_t)src->d_namelen;
#else // not defined(_DIRENT_HAVE_D_NAMLEN)
    return strnlen(src->d_name, LIMIT_STRLEN);
#endif // defined(_DIRENT_HAVE_D_NAMLEN)
}

static inline enum filetype_t
extract_filetype_from_dirent(struct dirent * src)
{
#if !defined(_DIRENT_HAVE_D_TYPE)
#error "can't have nice things on this system, wait for a patch to support stat"
#endif // !defined(_DIRENT_HAVE_D_TYPE)
    unsigned char d_type = src->d_type;
    enum filetype_t type = FTYPE_UNKNOWN;
    switch (d_type)
    {
        case DT_BLK:
            type = FTYPE_BLOCK;
            break;
        case DT_CHR:
            type = FTYPE_CHARDEV;
            break;
        case DT_DIR:
            type = FTYPE_DIR;
            break;
        case DT_FIFO:
            type = FTYPE_FIFO;
            break;
        case DT_LNK:
            type = FTYPE_SYMLINK;
            break;
        case DT_REG:
            type = FTYPE_REGULAR;
            break;
        case DT_SOCK:
            type = FTYPE_SOCK;
            break;
        default:
            // initialized to unknown
            break;
    }
    return type;
}

static inline bool
check_ignore_policy_dirent(struct dirent * src)
{
    if (src && src->d_name)
    {
        size_t sz = extract_name_size_from_dirent(src);
        if (1 <= sz && '.' == src->d_name[0])
        {
            return true;
        }
    }
    return false;
}

struct file_record_t
{
    struct stat fr_sstat;
    char name[];
};

static int
consume_dirent(struct dirent * src)
{
    output("%s %hhd %d", src->d_name, src->d_type, src->d_ino);
    return 0;
}

static void
parse_dir(char const * target)
{
    DIR *dir = NULL;
    struct dirent *current = NULL;
    errno = 0;
    dir = opendir(target);
    log_debug("%p", dir);
    if (NULL == dir)
    {
        log_at_libc_err("on opening directory %s", target);
        return;
    }
    while (1)
    {
        errno = 0;
        current = readdir(dir);
        log_debug("current: %p", current);
        if (NULL == current)
        {
            /* it can be end of a directory... */
            if (0 == errno)
            {
                break;
            }
            /* ... OR a readdir error */
            log_at_libc_err("on access in %s", target);
            continue;
        }
        bool should_skip = check_ignore_policy_dirent(current);
        if (should_skip)
        {
            continue;
        }
        consume_dirent(current);
    }
    if (0 != closedir (dir))
    {
        log_at_libc_err("on closing directory %s", target);
    }
}

int
print_multiple_dirs(char * dir_array[], size_t sz)
{
    log_debug("sz %lu", sz);
    for (size_t i = 0; i < sz; ++i)
    {
        if (NULL == dir_array[i])
        {
            return -1;
        }
        log_debug("%s", dir_array[i]);
        parse_dir(dir_array[i]);
    }
    return 0;
}

/* thanks chromium and SO */
#define COUNT_OF(x) ((sizeof(x)/sizeof(0[x])) / ((size_t)(!(sizeof(x) % sizeof(0[x]))))) /* NOLINT(readability-misplaced-array-index) */


int
main(int argc, char *argv[])
{
    log_debug("argc %d", argc);
    if (1 == argc)
    {
        static char * def_targets[] = {".", NULL};
        print_multiple_dirs(def_targets, COUNT_OF(def_targets) - 1);
    }
    else
    {
        print_multiple_dirs(&argv[1], argc - 1);
    }
    return 0;
}
