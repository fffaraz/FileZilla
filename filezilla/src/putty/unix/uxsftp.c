/*
 * uxsftp.c: the Unix-specific parts of PSFTP and PSCP.
 */

#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include <utime.h>
#include <errno.h>
#include <assert.h>
#include <sys/mman.h>

#include "putty.h"
#include "ssh.h"
#include "psftp.h"
#include "fzsftp.h"

#if HAVE_GLOB_H
#include <glob.h>
#endif

char *x_get_default(const char *key)
{
    return NULL;                       /* this is a stub */
}

void platform_get_x11_auth(struct X11Display *display, Conf *conf)
{
    /* Do nothing, therefore no auth. */
}
const bool platform_uses_x11_unix_by_default = true;

/*
 * Default settings that are specific to PSFTP.
 */
char *platform_default_s(const char *name)
{
    return NULL;
}

bool platform_default_b(const char *name, bool def)
{
    return def;
}

int platform_default_i(const char *name, int def)
{
    return def;
}

FontSpec *platform_default_fontspec(const char *name)
{
    return fontspec_new("");
}

Filename *platform_default_filename(const char *name)
{
    if (!strcmp(name, "LogFileName"))
        return filename_from_str("putty.log");
    else
        return filename_from_str("");
}

int filexfer_get_userpass_input(Seat *seat, prompts_t *p, bufchain *input)
{
    int ret;
    ret = cmdline_get_passwd_input(p);
    if (ret == -1)
        ret = console_get_userpass_input(p);
    return ret;
}

/*
 * Set local current directory. Returns NULL on success, or else an
 * error message which must be freed after printing.
 */
char *psftp_lcd(char *dir)
{
    if (chdir(dir) < 0)
        return dupprintf("%s: chdir: %s", dir, strerror(errno));
    else
        return NULL;
}

/*
 * Get local current directory. Returns a string which must be
 * freed.
 */
char *psftp_getcwd(void)
{
    char *buffer, *ret;
    size_t size = 256;

    buffer = snewn(size, char);
    while (1) {
        ret = getcwd(buffer, size);
        if (ret != NULL)
            return ret;
        if (errno != ERANGE) {
            sfree(buffer);
            return dupprintf("[cwd unavailable: %s]", strerror(errno));
        }
        /*
         * Otherwise, ERANGE was returned, meaning the buffer
         * wasn't big enough.
         */
        sgrowarray(buffer, size, size);
    }
}

enum read_state
{
    ok,
    error,
    eof
};

struct RFile {
#if 1
    int mapping_;
    uint8_t * memory_;
    size_t memory_size_;
    int state;
    uint8_t * buffer_;
    int remaining_;
#else
    int fd;
#endif
};

RFile *open_existing_file(const char *name, uint64_t offset,
                          unsigned long *mtime, unsigned long *atime,
                          long *perms)
{
#if 1
    fzprintf(sftp_io_open, "%"PRIu64, offset);
    char * s = priority_read();

    if (s[1] == '-') {
        return NULL;
    }

    char * p = s + 1;

    int mapping = next_int(&p);
    size_t memory_size = next_int(&p);

    sfree(s);

    uint8_t* memory = mmap(NULL, memory_size, PROT_READ|PROT_WRITE, MAP_SHARED, mapping, 0);
    if (!memory || memory == MAP_FAILED) {
        int err = errno;
        fzprintf(sftpError, "mmap failed: %d %s", err, strerror(err));
        return NULL;
    }

    RFile *ret;
    ret = snew(RFile);
    ret->mapping_ = mapping;
    ret->memory_ = memory;
    ret->memory_size_ = memory_size;
    ret->remaining_ = 0;
    ret->buffer_  = NULL;
    ret->state = ok;

    return ret;
#else
    int fd;
    RFile *ret;

    fd = open(name, O_RDONLY);
    if (fd < 0)
    {
        fzprintf(sftpStatus, "%s: open: %s", name, strerror(errno));
        return NULL;
    }

    ret = snew(RFile);
    ret->fd = fd;

    if (size || mtime || atime || perms) {
        struct stat statbuf;
        if (fstat(fd, &statbuf) < 0) {
            fzprintf(sftpStatus, "%s: stat: %s", name, strerror(errno));
            memset(&statbuf, 0, sizeof(statbuf));
        }

        if (size)
            *size = statbuf.st_size;

        if (mtime)
            *mtime = statbuf.st_mtime;

        if (atime)
            *atime = statbuf.st_atime;

        if (perms)
            *perms = statbuf.st_mode;
    }

    return ret;
#endif
}

int read_from_file(RFile *f, void *buffer, int length)
{
#if 1
    if (f->state == ok && !f->remaining_) {
        fznotify1(sftp_io_nextbuf, 0);
        char * s = priority_read();
        if (s[1] == '-') {
            f->state = error;
            return -1;
        }
        else if (s[1] == 0) {
            f->state = eof;
        }
        else {
            char * p = s + 1;
            f->buffer_ = f->memory_ + next_int(&p);
            f->remaining_ = (int)next_int(&p);
        }
        sfree(s);
    }
    if (f->state == eof) {
        return 0;
    }
    else if (f->state == error) {
        return -1;
    }

    if (length > f->remaining_) {
        length = f->remaining_;
    }
    memcpy(buffer, f->buffer_, length);
    f->remaining_ -= length;
    f->buffer_ += length;
    return length;
#else
    return read(f->fd, buffer, length);
#endif
}

void close_rfile(RFile *f)
{
    if (!f) {
        return;
    }
#if 1
    munmap(f->memory_, f->memory_size_);
#else
    close(f->fd);
#endif
    sfree(f);
}

struct WFile {
#if 1
    int mapping_;
    uint8_t * memory_;
    size_t memory_size_;
    int state;
    uint8_t * buffer_;
    int remaining_;
    int size_;
#else
    int fd;
    char *name;
#endif
};

WFile *open_new_file(const char *name, long perms)
{
#if 1
    fznotify1(sftp_io_open, 0);
    char * s = priority_read();
    if (s[1] == '-') {
        return NULL;
    }

    char * p = s + 1;

    int mapping = next_int(&p);
    size_t memory_size = next_int(&p);

    sfree(s);

    uint8_t* memory = mmap(0, memory_size, PROT_READ|PROT_WRITE, MAP_SHARED, mapping, 0);
    if (!memory || memory == MAP_FAILED) {
        int err = errno;
        fzprintf(sftpError, "mmap failed: %d %s", err, strerror(err));
        return NULL;
    }

    WFile *ret;
    ret = snew(WFile);
    ret->mapping_ = mapping;
    ret->memory_ = memory;
    ret->memory_size_ = memory_size;
    ret->remaining_ = 0;
    ret->buffer_  = NULL;
    ret->state = ok;
    ret->size_ = 0;

    return ret;
#else
    int fd;
    WFile *ret;

    fd = open(name, O_CREAT | O_TRUNC | O_WRONLY,
              (mode_t)(perms ? perms : 0666));
    if (fd < 0)
        return NULL;

    ret = snew(WFile);
    ret->fd = fd;
    ret->name = dupstr(name);

    return ret;
#endif
}


WFile *open_existing_wfile(const char *name, uint64_t *size)
{
#if 1
    fzprintf(sftp_io_open, "%"PRIu64, (uint64_t)-1);
    char * s = priority_read();
    if (s[1] == '-') {
        return NULL;
    }

    char * p = s + 1;

    int mapping = next_int(&p);
    size_t memory_size = next_int(&p);
    if (size) {
        *size = next_int(&p);
    }

    sfree(s);

    uint8_t* memory = mmap(0, memory_size, PROT_READ|PROT_WRITE, MAP_SHARED, mapping, 0);
    if (!memory || memory == MAP_FAILED) {
        int err = errno;
        fzprintf(sftpError, "mmap failed: %d %s", err, strerror(err));
        return NULL;
    }

    WFile *ret;
    ret = snew(WFile);
    ret->mapping_ = mapping;
    ret->memory_ = memory;
    ret->memory_size_ = memory_size;
    ret->remaining_ = 0;
    ret->buffer_ = NULL;
    ret->state = ok;
    ret->size_ = 0;

    return ret;
#else
    int fd;
    WFile *ret;

    fd = open(name, O_APPEND | O_WRONLY);
    if (fd < 0)
        return NULL;

    ret = snew(WFile);
    ret->fd = fd;
    ret->name = dupstr(name);

    if (size) {
        struct stat statbuf;
        if (fstat(fd, &statbuf) < 0) {
            fprintf(stderr, "%s: stat: %s\n", name, strerror(errno));
            memset(&statbuf, 0, sizeof(statbuf));
        }

        *size = statbuf.st_size;
    }

    return ret;
#endif
}

int write_to_file(WFile *f, void *buffer, int length)
{
#if 1
    if (f->state == ok && !f->remaining_) {
        fznotify1(sftp_io_nextbuf, f->size_ - f->remaining_);
        char * s = priority_read();
        if (s[1] == '-') {
            f->state = error;
            return -1;
        }
        else if (s[1] == 0) {
            f->state = eof;
        }
        else {
            char * p = s + 1;
            f->buffer_ = f->memory_ + next_int(&p);
            f->remaining_ = (int)next_int(&p);
            f->size_ = f->remaining_;
        }
        sfree(s);
    }
    if (f->state == eof) {
        return 0;
    }
    else if (f->state == error) {
        return -1;
    }

    if (length > f->remaining_) {
        length = f->remaining_;
    }
    memcpy(f->buffer_, buffer, length);
    f->remaining_ -= length;
    f->buffer_ += length;
    return length;
#else
    char *p = (char *)buffer;
    int so_far = 0;

    /* Keep trying until we've really written as much as we can. */
    while (length > 0) {
        int ret = write(f->fd, p, length);

        if (ret < 0)
            return ret;

        if (ret == 0)
            break;

        p += ret;
        length -= ret;
        so_far += ret;
    }

    return so_far;
#endif
}

int finalize_wfile(WFile *f)
{
#if 1
    if (f->state == eof) {
        return 1;
    }
    if (f->state != ok) {
        return 0;
    }
    fznotify1(sftp_io_finalize, f->size_ - f->remaining_);
    char * s = priority_read();
    if (s[1] != '1') {
        f->state = error;
        return 0;
    }
    f->state = eof;
#endif
    return 1;
}

void set_file_times(WFile *f, unsigned long mtime, unsigned long atime)
{
#if TODO
    struct utimbuf ut;

    ut.actime = atime;
    ut.modtime = mtime;

    utime(f->name, &ut);
#endif
}

/* Closes and frees the WFile */
void close_wfile(WFile *f)
{
    if (!f) {
        return;
    }
#if 1
    munmap(f->memory_, f->memory_size_);
#else
    close(f->fd);
    sfree(f->name);
#endif
    sfree(f);
}

/* Seek offset bytes through file, from whence, where whence is
   FROM_START, FROM_CURRENT, or FROM_END */
int seek_file(WFile *f, uint64_t offset, int whence)
{
#if TODO
    int lseek_whence;

    switch (whence) {
    case FROM_START:
        lseek_whence = SEEK_SET;
        break;
    case FROM_CURRENT:
        lseek_whence = SEEK_CUR;
        break;
    case FROM_END:
        lseek_whence = SEEK_END;
        break;
    default:
        return -1;
    }

    return lseek(f->fd, offset, lseek_whence) >= 0 ? 0 : -1;
#else
    return -1;
#endif
}

uint64_t get_file_posn(WFile *f)
{
#if TODO
    return lseek(f->fd, (off_t) 0, SEEK_CUR);
#else
    return (uint64_t)-1;
#endif
}

int file_type(const char *name)
{
    struct stat statbuf;

    if (stat(name, &statbuf) < 0) {
        if (errno != ENOENT)
            fprintf(stderr, "%s: stat: %s\n", name, strerror(errno));
        return FILE_TYPE_NONEXISTENT;
    }

    if (S_ISREG(statbuf.st_mode))
        return FILE_TYPE_FILE;

    if (S_ISDIR(statbuf.st_mode))
        return FILE_TYPE_DIRECTORY;

    return FILE_TYPE_WEIRD;
}

struct DirHandle {
    DIR *dir;
};

DirHandle *open_directory(const char *name, const char **errmsg)
{
    DIR *dir;
    DirHandle *ret;

    dir = opendir(name);
    if (!dir) {
        *errmsg = strerror(errno);
        return NULL;
    }

    ret = snew(DirHandle);
    ret->dir = dir;
    return ret;
}

char *read_filename(DirHandle *dir)
{
    struct dirent *de;

    do {
        de = readdir(dir->dir);
        if (de == NULL)
            return NULL;
    } while ((de->d_name[0] == '.' &&
              (de->d_name[1] == '\0' ||
               (de->d_name[1] == '.' && de->d_name[2] == '\0'))));

    return dupstr(de->d_name);
}

void close_directory(DirHandle *dir)
{
    closedir(dir->dir);
    sfree(dir);
}

int test_wildcard(const char *name, bool cmdline)
{
    struct stat statbuf;

    if (stat(name, &statbuf) == 0) {
        return WCTYPE_FILENAME;
    } else if (cmdline) {
        /*
         * On Unix, we never need to parse wildcards coming from
         * the command line, because the shell will have expanded
         * them into a filename list already.
         */
        return WCTYPE_NONEXISTENT;
    } else {
#if HAVE_GLOB_H
        glob_t globbed;
        int ret = WCTYPE_NONEXISTENT;

        if (glob(name, GLOB_ERR, NULL, &globbed) == 0) {
            if (globbed.gl_pathc > 0)
                ret = WCTYPE_WILDCARD;
            globfree(&globbed);
        }

        return ret;
#else
        /* On a system without glob.h, we just have to return a
         * failure code */
        return WCTYPE_NONEXISTENT;
#endif
    }
}

/*
 * Actually return matching file names for a local wildcard.
 */
#if HAVE_GLOB_H
struct WildcardMatcher {
    glob_t globbed;
    int i;
};
WildcardMatcher *begin_wildcard_matching(const char *name) {
    WildcardMatcher *ret = snew(WildcardMatcher);

    if (glob(name, 0, NULL, &ret->globbed) < 0) {
        sfree(ret);
        return NULL;
    }

    ret->i = 0;

    return ret;
}
char *wildcard_get_filename(WildcardMatcher *dir) {
    if (dir->i < dir->globbed.gl_pathc) {
        return dupstr(dir->globbed.gl_pathv[dir->i++]);
    } else
        return NULL;
}
void finish_wildcard_matching(WildcardMatcher *dir) {
    globfree(&dir->globbed);
    sfree(dir);
}
#else
WildcardMatcher *begin_wildcard_matching(const char *name)
{
    return NULL;
}
char *wildcard_get_filename(WildcardMatcher *dir)
{
    unreachable("Can't construct a valid WildcardMatcher without <glob.h>");
}
void finish_wildcard_matching(WildcardMatcher *dir)
{
    unreachable("Can't construct a valid WildcardMatcher without <glob.h>");
}
#endif

char *stripslashes(const char *str, bool local)
{
    char *p;

    /*
     * On Unix, we do the same thing regardless of the 'local'
     * parameter.
     */
    p = strrchr(str, '/');
    if (p) str = p+1;

    return (char *)str;
}

bool vet_filename(const char *name)
{
    if (strchr(name, '/'))
        return false;

    if (name[0] == '.' && (!name[1] || (name[1] == '.' && !name[2])))
        return false;

    return true;
}

bool create_directory(const char *name)
{
    return mkdir(name, 0777) == 0;
}

char *dir_file_cat(const char *dir, const char *file)
{
    ptrlen dir_pl = ptrlen_from_asciz(dir);
    return dupcat(
        dir, ptrlen_endswith(dir_pl, PTRLEN_LITERAL("/"), NULL) ? "" : "/",
        file);
}

/*
 * Do a select() between all currently active network fds and
 * optionally stdin, using cli_main_loop.
 */

struct ssh_sftp_mainloop_ctx {
    bool include_stdin, no_fds_ok;
    int toret;
};
static bool ssh_sftp_pw_setup(void *vctx, pollwrapper *pw)
{
    struct ssh_sftp_mainloop_ctx *ctx = (struct ssh_sftp_mainloop_ctx *)vctx;
    int fdstate, rwx;

    if (!ctx->no_fds_ok && !toplevel_callback_pending() &&
        first_fd(&fdstate, &rwx) < 0) {
        ctx->toret = -1;
        return false; /* terminate cli_main_loop */
    }

    if (ctx->include_stdin)
        pollwrap_add_fd_rwx(pw, 0, SELECT_R);

    return true;
}
static void ssh_sftp_pw_check(void *vctx, pollwrapper *pw)
{
    struct ssh_sftp_mainloop_ctx *ctx = (struct ssh_sftp_mainloop_ctx *)vctx;

    if (ctx->include_stdin && pollwrap_check_fd_rwx(pw, 0, SELECT_R))
        ctx->toret = 1;
}
static bool ssh_sftp_mainloop_continue(void *vctx, bool found_any_fd,
                                       bool ran_any_callback)
{
    struct ssh_sftp_mainloop_ctx *ctx = (struct ssh_sftp_mainloop_ctx *)vctx;
    if (ctx->toret != 0 || found_any_fd || ran_any_callback)
        return false;                  /* finish the loop */
    return true;
}
static int ssh_sftp_do_select(bool include_stdin, bool no_fds_ok)
{
    struct ssh_sftp_mainloop_ctx ctx[1];
    ctx->include_stdin = include_stdin;
    ctx->no_fds_ok = no_fds_ok;
    ctx->toret = 0;

    cli_main_loop(ssh_sftp_pw_setup, ssh_sftp_pw_check,
                  ssh_sftp_mainloop_continue, ctx);

    return ctx->toret;
}

/*
 * Wait for some network data and process it.
 */
int ssh_sftp_loop_iteration(void)
{
    return ssh_sftp_do_select(false, false);
}

/*
 * Read a PSFTP command line from stdin.
 */
char *ssh_sftp_get_cmdline(const char *prompt, bool no_fds_ok)
{
    int ret;

    char* line = get_input_pushback();
    if (line != 0)
        return line;


    while (1) {
        ret = ssh_sftp_do_select(true, no_fds_ok);
        if (ret < 0) {
            printf("connection died\n");
            sfree(line);
            return NULL;               /* woop woop */
        }
        if (ret > 0) {
            int error = 0;
            line = read_input_line(0, &error);
            if (error)
                return NULL;

            if (line == NULL)
                continue;

            if (line[0] == '-')
            {
                ProcessQuotaCmd(line);
                sfree(line);
                line = NULL;
            }
            else
                return line;
        }
    }
}

void frontend_net_error_pending(void) {}

void platform_psftp_pre_conn_setup(LogPolicy *lp) {}

const bool buildinfo_gtk_relevant = false;

/*
 * Main program: do platform-specific initialisation and then call
 * psftp_main().
 */
int main(int argc, char *argv[])
{
    uxsel_init();
    return psftp_main(argc, argv);
}
