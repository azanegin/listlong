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
 * TODO: dev maj/min print, blocksize
 *
 * I would prefer to use some string library, but that would be not-my-code.
 *
 * Sorting by default in ls is charcode-based, so we go that route.
 * https://www.gnu.org/software/coreutils/manual/html_node/Sorting-the-output.html
 *
 *
 * */
#include <unistd.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <dirent.h>
#include <stdint.h>
#include <errno.h>
#include <stdbool.h>
#include <stdarg.h>
#include <assert.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>


static size_t LIMIT_STRLEN = 4096;
#if !defined(PATH_MAX)
#define PATH_MAX LIMIT_STRLEN
#endif //!defined(PATH_MAX)
/* should include <langinfo.h> and do i18n */
#define TIME_FMT_STR "%b %e  %Y"

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
static char const FT_CHAR_ARR[] = {'u', 'f', 'c', 'd', 'b', '-', 'l', 's'};

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

static inline int
output_l(char const * format, ...)
{
    int retval = 0;
    va_list args;
    va_start(args, format);
    retval = vfprintf(stdout,  format, args);
    va_end(args);
    return retval;
}

//#define DEBUG 1

#if defined(DEBUG)
/* would prefer func, but want __line__ to work without backtrace */
#define log_debug(format, ...) fprintf(stderr, "[%s]: " format "\n", __func__, ##__VA_ARGS__)
#else // not defined(DEBUG)
#define log_debug(format, ...)
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
extract_name_size_from_dirent(struct dirent const * src)
{
#if   defined(_DIRENT_HAVE_D_NAMLEN)
    static_assert(sizeof(src->d_namelen) <= sizeof(size_t));
    return (size_t)src->d_namelen;
#elif defined(_DIRENT_HAVE_D_RECLEN)
    static_assert(sizeof(src->d_reclen) <= sizeof(size_t));
    return src->d_reclen - offsetof(struct dirent, d_name);
#else //not defined(_DIRENT_HAVE_D_NAMLEN) and not defined(_DIRENT_HAVE_D_RECLEN)
    return strnlen(src->d_name, LIMIT_STRLEN);
#endif
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

static inline int
check_ignore_policy_dirent(struct dirent const * src)
{
    if (src && src->d_name)
    {
        size_t sz = extract_name_size_from_dirent(src);
        if (1 <= sz && '.' == src->d_name[0])
        {
            return 0;
        }
    }
    return 1;
}

struct file_record_t
{
    struct dirent * fr_dirent;
    struct stat * fr_s_stat;
    enum filetype_t fr_ft;
    char * fr_link_target;
    ssize_t fr_link_len;
};

struct db_t
{
    struct dirent ** namelist;
    struct file_record_t * records;
};

#if 0
static char *
concat_path(char const * at, size_t sz_at, struct dirent * target)
{
    char * buf = malloc(sz_at + /* for a slash */ 1 + extract_name_size_from_dirent(target) + /* for nullterm */ 1);
    if (NULL == buf)
    {
        return NULL;
    }
    buf = strncat(buf, at, strlen(at));
    buf = strncat(buf, "/", 2);
    buf = strncat(buf, target->d_name, extract_name_size_from_dirent(target));
    char * retval = realpath(buf, NULL);
    if (NULL == retval)
    {
        log_at_libc_err("realpath");
        return NULL;
    }
    free(buf);
    return retval;
}
#endif //0

static struct stat *
stat_dirent(int dirstream_fd, struct dirent * target)
{
    // char * path = concat_path(at, sz_at, target);
    errno = 0;
    struct stat * st = malloc(sizeof(struct stat));
    if (NULL == st)
    {
        log_at_libc_err("malloc for stat");
        return NULL;
    }
    int retval = fstatat(dirstream_fd, target->d_name, st, AT_SYMLINK_NOFOLLOW);
    if (-1 == retval)
    {
        log_at_libc_err("fstatat");
        free(st);
        return NULL;
    }
    return st;
}

static ssize_t
parse_dir(char const * target, struct db_t * out)
{
    errno = 0;
    int n = scandir(
            target,
            &(out->namelist),
            check_ignore_policy_dirent,
            alphasort
            );
    if (n == -1)
    {
        log_at_libc_err("scandir error");
        return -1;
    }
    DIR *dir = opendir(target);
    if (NULL == dir)
    {
        log_at_libc_err("opendir");
        return -1;
    }
    int fd = dirfd(dir);
    if (-1 == fd)
    {
        log_at_libc_err("dirfd");
        return -1;
    }
    struct file_record_t * rec_arr = calloc(n, sizeof(struct file_record_t));
    if (NULL == rec_arr)
    {
        log_at_libc_err("on calloc of rec_arr");
        return -1;
    }
    for (size_t i = 0; i < n; ++i)
    {
        rec_arr[i].fr_dirent = out->namelist[i];
        rec_arr[i].fr_ft = extract_filetype_from_dirent(out->namelist[i]);
        rec_arr[i].fr_s_stat = stat_dirent(fd, out->namelist[i]);
        if (FTYPE_SYMLINK == rec_arr[i].fr_ft)
        {
            rec_arr[i].fr_link_target = malloc(PATH_MAX);
            if (NULL != rec_arr[i].fr_link_target)
            {
                ssize_t sz = readlinkat(fd, out->namelist[i]->d_name, rec_arr[i].fr_link_target, PATH_MAX);
                if (-1 == sz)
                {
                    log_at_libc_err("readlinkat %s", out->namelist[i]->d_name);
                    free(rec_arr[i].fr_link_target);
                    rec_arr[i].fr_link_target = NULL;
                }
                else
                {
                    rec_arr[i].fr_link_target[sz] = '\0';
                }
                rec_arr[i].fr_link_len = sz;
            }
        }
        else
        {
            rec_arr[i].fr_link_target = NULL;
            rec_arr[i].fr_link_len = -1;
        }
    }
    if (0 != closedir(dir))
    {
        log_at_libc_err("on closing directory %s", target);
    }
    out->records = rec_arr;
    return n;
}

/* NOT THREAD-SAFE */
static inline void
out_perms(mode_t const perms)
{
    static char permbuf[] = "---------";
    int i = 0;
    permbuf[i++] =(perms & S_IRUSR) ? 'r' : '-';
    permbuf[i++] =(perms & S_IWUSR) ? 'w' : '-';
    permbuf[i++] =(perms & S_IXUSR) ? 'x' : '-';
    permbuf[i++] =(perms & S_IRGRP) ? 'r' : '-';
    permbuf[i++] =(perms & S_IWGRP) ? 'w' : '-';
    permbuf[i++] =(perms & S_IXGRP) ? 'x' : '-';
    permbuf[i++] =(perms & S_IROTH) ? 'r' : '-';
    permbuf[i++] =(perms & S_IWOTH) ? 'w' : '-';
    permbuf[i++] =(perms & S_IXOTH) ? 'x' : '-';
    output_l("%s ", permbuf);
}

static void
out_name(struct file_record_t * record)
{
    assert(NULL != record);
    if (FTYPE_SYMLINK == record->fr_ft && NULL != record->fr_link_target)
    {
        output("%s -> %s", record->fr_dirent->d_name, record->fr_link_target);
    }
    else
    {
        output("%s ", record->fr_dirent->d_name);
    }
}

static inline void
consume_record(struct file_record_t * record)
{
    output_l("%c", FT_CHAR_ARR[record->fr_ft]);
    out_perms(record->fr_s_stat->st_mode);

    output_l("%lu ", record->fr_s_stat->st_nlink);

    // TODO: cache names
    struct passwd * pwd = getpwuid(record->fr_s_stat->st_uid);
    if (NULL != pwd && NULL != pwd->pw_name)
    {
        output_l("%s ", pwd->pw_name);
    }
    else
    {
        output_l("%lu ", record->fr_s_stat->st_uid);
    }
    struct group * grp = getgrgid(record->fr_s_stat->st_gid);
    if (NULL != grp && NULL != grp->gr_name)
    {
        output_l("%s ", grp->gr_name);
    }
    else
    {
        output_l("%lu ", record->fr_s_stat->st_gid);
    }

    output_l("%10lu ", record->fr_s_stat->st_size);

    struct tm _tm = {};
    char time_str_buf[20];
    gmtime_r(&(record->fr_s_stat->st_mtim.tv_sec), &_tm);
    strftime(time_str_buf, 20, TIME_FMT_STR, &_tm);
    output_l("%s ", time_str_buf);
    out_name(record);
    free(record->fr_s_stat);
    free(record->fr_dirent);
    if (NULL != record->fr_link_target)
    {
        free(record->fr_link_target);
    }
}

static inline size_t
count_total(struct file_record_t * records, ssize_t rec_arr_sz)
{
    size_t total = 0;
    for (size_t i = 0; i < rec_arr_sz; ++i)
    {
        total += records[i].fr_s_stat->st_blocks;
    }
    return total;
}

static void
consume_dir(struct file_record_t * records, ssize_t rec_arr_sz)
{
    size_t total = count_total(records, rec_arr_sz);
    output("total %ld", total);
    for (size_t i = 0; i < rec_arr_sz; ++i)
    {
        consume_record(&records[i]);
    }
    free(records);
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
        struct db_t db;
        ssize_t rec_arr_sz = parse_dir(dir_array[i], &db);
        consume_dir(db.records, rec_arr_sz);
        free(db.namelist);
    }
    return 0;
}

/* thanks chromium and SO */
#define STATIC_COUNT_OF(x) ((sizeof(x)/sizeof(0[x])) / ((size_t)(!(sizeof(x) % sizeof(0[x]))))) /* NOLINT(readability-misplaced-array-index) */

int
main(int argc, char *argv[])
{
    log_debug("argc %d", argc);
    if (1 == argc)
    {
        static char * def_targets[] = {".", NULL};
        print_multiple_dirs(def_targets, STATIC_COUNT_OF(def_targets) - 1);
    }
    else
    {
        print_multiple_dirs(&argv[1], argc - 1);
    }
    return 0;
}
