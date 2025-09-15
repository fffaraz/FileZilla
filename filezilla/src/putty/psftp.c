/*
 * psftp.c: (platform-independent) front end for PSFTP.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#include <limits.h>

#ifndef _WINDOWS
#include <locale.h>
#endif

#define PUTTY_DO_GLOBALS
#include "putty.h"
#include "psftp.h"
#include "storage.h"
#include "ssh.h"
#include "sftp.h"

const char *const appname = "FZSFTP";

/*
 * Since SFTP is a request-response oriented protocol, it requires
 * no buffer management: when we send data, we stop and wait for an
 * acknowledgement _anyway_, and so we can't possibly overfill our
 * send buffer.
 */

static int psftp_connect(char *userhost, char *user, int portnumber);
static int do_sftp_init(void);
static void do_sftp_cleanup(void);

/* ----------------------------------------------------------------------
 * sftp client state.
 */

static char *pwd, *homedir;
static LogContext *psftp_logctx = NULL;
static Backend *backend;
static Conf *conf;
static bool sent_eof = false;

/* ------------------------------------------------------------
 * Seat vtable.
 */

static size_t psftp_output(Seat *, bool is_stderr, const void *, size_t);
static bool psftp_eof(Seat *);

static const SeatVtable psftp_seat_vt = {
    .output = psftp_output,
    .eof = psftp_eof,
    .get_userpass_input = filexfer_get_userpass_input,
    .notify_remote_exit = nullseat_notify_remote_exit,
    .connection_fatal = console_connection_fatal,
    .update_specials_menu = nullseat_update_specials_menu,
    .get_ttymode = nullseat_get_ttymode,
    .set_busy_status = nullseat_set_busy_status,
    .verify_ssh_host_key = console_verify_ssh_host_key,
    .confirm_weak_crypto_primitive = console_confirm_weak_crypto_primitive,
    .confirm_weak_cached_hostkey = console_confirm_weak_cached_hostkey,
    .is_utf8 = nullseat_is_never_utf8,
    .echoedit_update = nullseat_echoedit_update,
    .get_x_display = nullseat_get_x_display,
    .get_windowid = nullseat_get_windowid,
    .get_window_pixel_size = nullseat_get_window_pixel_size,
    .stripctrl_new = console_stripctrl_new,
    .set_trust_status = nullseat_set_trust_status_vacuously,
    .verbose = cmdline_seat_verbose,
    .interactive = nullseat_interactive_yes,
    .get_cursor_position = nullseat_get_cursor_position,
};
static Seat psftp_seat[1] = {{ &psftp_seat_vt }};

/* ----------------------------------------------------------------------
 * A nasty loop macro that lets me get an escape-sequence sanitised
 * version of a string for display, and free it automatically
 * afterwards.
 */
static StripCtrlChars *string_scc;
#define with_stripctrl(varname, input)                                  \
    for (char *varname = stripctrl_string(string_scc, input); varname;  \
         sfree(varname), varname = NULL)

/* ----------------------------------------------------------------------
 * Manage sending requests and waiting for replies.
 */
struct sftp_packet *sftp_wait_for_reply(struct sftp_request *req)
{
    struct sftp_packet *pktin;
    struct sftp_request *rreq;

    sftp_register(req);
    pktin = sftp_recv();
    if (pktin == NULL) {
        seat_connection_fatal(
            psftp_seat, "did not receive SFTP response packet from server");
    }
    rreq = sftp_find_request(pktin);
    if (rreq != req) {
        seat_connection_fatal(
            psftp_seat,
            "unable to understand SFTP response packet from server: %s",
            fxp_error());
    }
    return pktin;
}

/* ----------------------------------------------------------------------
 * Higher-level helper functions used in commands.
 */

/*
 * Attempt to canonify a pathname starting from the pwd. If
 * canonification fails, at least fall back to returning a _valid_
 * pathname (though it may be ugly, eg /home/simon/../foobar).
 *
 * If parent_only is non-zero, only the parent will be canonified.
 * e.g. if called with foo/bar/baz, only foo/bar/ will be canonicied
 * and baz appended to the result. This is needed to delete symbolic
 * links as FXP_REALPATH would resolve the link if called with the
 * full path.
 */
char *canonify(const char *name, bool parent_only)
{
    char *fullname, *canonname;
    struct sftp_packet *pktin;
    struct sftp_request *req;
    char* suffix = NULL;

    if (name[0] == '/') {
        fullname = dupstr(name);
    } else {
        const char *slash;
        if (pwd[strlen(pwd) - 1] == '/')
            slash = "";
        else
            slash = "/";
        fullname = dupcat(pwd, slash, name);
    }

    if (parent_only) {
        suffix = strrchr(fullname, '/');
        if (!suffix) {
            /* Cosmic rays make this happen */
            sfree(fullname);
            return NULL;
        }
        else if (suffix == fullname) {
            return fullname;
        }
        else {
            *suffix = 0;
            suffix = dupstr(++suffix);
        }
    }

    req = fxp_realpath_send(fullname);
    pktin = sftp_wait_for_reply(req);
    canonname = fxp_realpath_recv(pktin, req);

    if (canonname) {
        char* ret;
        sfree(fullname);
        if (!suffix)
            return canonname;
        if (*canonname && canonname[strlen(canonname) - 1] == '/')
            canonname[strlen(canonname) - 1] = 0;
        ret = dupcat(canonname, "/", suffix);
        sfree(canonname);
        sfree(suffix);
        return ret;
    } else {
        /*
         * Attempt number 2. Some FXP_REALPATH implementations
         * (glibc-based ones, in particular) require the _whole_
         * path to point to something that exists, whereas others
         * (BSD-based) only require all but the last component to
         * exist. So if the first call failed, we should strip off
         * everything from the last slash onwards and try again,
         * then put the final component back on.
         *
         * Special cases:
         *
         *  - if the last component is "/." or "/..", then we don't
         *    bother trying this because there's no way it can work.
         *
         *  - if the thing actually ends with a "/", we remove it
         *    before we start. Except if the string is "/" itself
         *    (although I can't see why we'd have got here if so,
         *    because surely "/" would have worked the first
         *    time?), in which case we don't bother.
         *
         *  - if there's no slash in the string at all, give up in
         *    confusion (we expect at least one because of the way
         *    we constructed the string).
         */

        size_t i;
        char *returnname;

        i = strlen(fullname);
        if (i > 2 && fullname[i - 1] == '/')
            fullname[--i] = '\0';      /* strip trailing / unless at pos 0 */
        while (i > 0 && fullname[--i] != '/');

        /*
         * Give up on special cases.
         */
        if (fullname[i] != '/' ||      /* no slash at all */
            !strcmp(fullname + i, "/.") ||        /* ends in /. */
            !strcmp(fullname + i, "/..") ||        /* ends in /.. */
            !strcmp(fullname, "/")) {

            if (!suffix)
                return fullname;

            if (*fullname && fullname[strlen(fullname) - 1] == '/')
                fullname[strlen(fullname) - 1] = 0;
            returnname = dupcat(fullname, "/", suffix);
            sfree(fullname);
            sfree(suffix);
            return returnname;
        }

        /*
         * Now i points at the slash. Deal with the final special
         * case i==0 (ie the whole path was "/nonexistentfile").
         */
        fullname[i] = '\0';            /* separate the string */
        if (i == 0) {
            req = fxp_realpath_send("/");
        } else {
            req = fxp_realpath_send(fullname);
        }
        pktin = sftp_wait_for_reply(req);
        canonname = fxp_realpath_recv(pktin, req);

        if (!canonname) {
            /* Even that failed. Restore our best guess at the
             * constructed filename and give up */
            fullname[i] = '/';  /* restore slash and last component */

            if (!suffix)
                return fullname;

            if (*fullname && fullname[strlen(fullname) - 1] == '/')
                fullname[strlen(fullname) - 1] = 0;
            returnname = dupcat(fullname, "/", suffix);
            sfree(fullname);
            sfree(suffix);
            return returnname;
        }

        /*
         * We have a canonical name for all but the last path
         * component. Concatenate the last component and return.
         */
        returnname = dupcat(canonname,
                            canonname[strlen(canonname) - 1] ==
                            '/' ? "" : "/", fullname + i + 1, (!suffix || fullname[i + strlen(fullname + i + 1)] == '/') ? "" : "/", suffix);
        sfree(fullname);
        sfree(canonname);
        if (suffix)
            sfree(suffix);
        return returnname;
    }
}

static void not_connected(void)
{
    fzprintf(sftpError, "psftp: not connected to a host; use \"open host.name\"");
}

/* ----------------------------------------------------------------------
 * The meat of the `get' and `put' commands.
 */
int sftp_get_file(char *fname, char *outfname, bool restart)
{
    struct fxp_handle *fh;
    struct sftp_packet *pktin;
    struct sftp_request *req;
    struct fxp_xfer *xfer;
    uint64_t offset;
    WFile *file;
    int ret, shown_err = false;
    struct fxp_attrs attrs;
    _fztimer timer;
    int winterval;

    req = fxp_stat_send(fname);
    pktin = sftp_wait_for_reply(req);
    if (!fxp_stat_recv(pktin, req, &attrs))
        attrs.flags = 0;

    req = fxp_open_send(fname, SSH_FXF_READ, NULL);
    pktin = sftp_wait_for_reply(req);
    fh = fxp_open_recv(pktin, req);

    if (!fh) {
        fzprintf(sftpError, "%s: open for read: %s", fname, fxp_error());
        return 0;
    }

    offset = 0;
    if (restart) {
        file = open_existing_wfile(outfname, &offset);
    } else {
        file = open_new_file(outfname, GET_PERMISSIONS(attrs, -1));
    }

    if (!file) {
        fzprintf(sftpError, "local: unable to open %s", outfname);

        req = fxp_close_send(fh);
        pktin = sftp_wait_for_reply(req);
        fxp_close_recv(pktin, req);

        return 2;
    }

    fzprintf(sftpInfo, "remote:%s => local:%s", fname, outfname);

    fz_timer_init(&timer);
    winterval = 0;

    /*
     * FIXME: we can use FXP_FSTAT here to get the file size, and
     * thus put up a progress bar.
     */
    ret = 1;
    xfer = xfer_download_init(fh, offset);
    while (!xfer_done(xfer)) {
        void *vbuf;
        int retd, len;
        int wpos, wlen;

        xfer_download_queue(xfer);
        pktin = sftp_recv();
        retd = xfer_download_gotpkt(xfer, pktin);
        if (retd <= 0) {
            if (!shown_err) {
                fzprintf(sftpError, "error while reading: %s", fxp_error());
                shown_err = true;
            }
            if (retd == INT_MIN)        /* pktin not even freed */
                sfree(pktin);
            ret = 0;
        }

        while (xfer_download_data(xfer, &vbuf, &len)) {
            unsigned char *buf = (unsigned char *)vbuf;

            wpos = 0;
            while (file && wpos < len) {
                wlen = write_to_file(file, buf + wpos, len - wpos);
                if (wlen <= 0) {
                    if (!shown_err) {
                        fzprintf(sftpError, "error while writing local file");
                        shown_err = true;
                    }
                    ret = 0;
                    xfer_set_error(xfer);
                    break;
                }
                wpos += wlen;
            }
            if (wpos < len) {               /* we had an error */
                ret = 0;
                xfer_set_error(xfer);
            }
            winterval += wpos;
            sfree(vbuf);
        }

        if (fz_timer_check(&timer)) {
            fzprintf(sftpTransfer, "%d", winterval);
            winterval = 0;
        }

    }

    xfer_cleanup(xfer);

    if (ret == 1) {
        if (!finalize_wfile(file)) {
            fzprintf(sftpError, "error while writing local file");
            ret = 0;
        }
    }

    close_wfile(file);

    req = fxp_close_send(fh);
    pktin = sftp_wait_for_reply(req);
    fxp_close_recv(pktin, req);

    return ret;
}

int pending_receive() {
    return ssh_pending_receive(backend);
}

int sftp_put_file(char *fname, char *outfname, int restart)
{
    struct fxp_handle *fh;
    struct fxp_xfer *xfer;
    struct sftp_packet *pktin;
    struct sftp_request *req;
    uint64_t offset = 0;
    RFile *file = 0;
    bool err = false, eof;
    struct fxp_attrs attrs;
    long permissions;
    _fztimer timer;
    int rinterval;

    attrs.flags = 0;
//FIXME    PUT_PERMISSIONS(attrs, permissions);
    if (restart) {
        req = fxp_open_send(outfname, SSH_FXF_WRITE, &attrs);
    } else {
        req = fxp_open_send(outfname,
                            SSH_FXF_WRITE | SSH_FXF_CREAT | SSH_FXF_TRUNC,
                            &attrs);
    }
    pktin = sftp_wait_for_reply(req);
    fh = fxp_open_recv(pktin, req);

    if (!fh) {
        fzprintf(sftpError, "%s: open for write: %s", outfname, fxp_error());
        return 0;
    }

    if (restart) {
        struct fxp_attrs attrs;
        int retd;

        req = fxp_fstat_send(fh);
        pktin = sftp_wait_for_reply(req);
        retd = fxp_fstat_recv(pktin, req, &attrs);

        if (!retd) {
            fzprintf(sftpError, "read size of %s: %s", outfname, fxp_error());
            err = true;
            goto cleanup;
        }
        if (!(attrs.flags & SSH_FILEXFER_ATTR_SIZE)) {
            fzprintf(sftpError, "read size of %s: size was not given", outfname);
            err = true;
            goto cleanup;
        }
        offset = attrs.size;
        fzprintf(sftpInfo, "reput: restarting at file position %"PRIu64, offset);
    } else {
        offset = 0;
    }

    file = open_existing_file(fname, offset, NULL, NULL, &permissions);
    if (!file) {
        fzprintf(sftpError, "local: unable to open %s", fname);
        err = true;
        goto cleanup;
    }
    fzprintf(sftpInfo, "local:%s => remote:%s\n", fname, outfname);

    fz_timer_init(&timer);
    rinterval = 0;

    /*
     * FIXME: we can use FXP_FSTAT here to get the file size, and
     * thus put up a progress bar.
     */
    xfer = xfer_upload_init(fh, offset);
    eof = false;
    while ((!err && !eof) || !xfer_done(xfer)) {
        char buffer[4096*4];
        int len, ret;

        while (xfer_upload_ready(xfer) && !err && !eof) {
            if (rinterval) {
                if (fz_timer_check(&timer)) {
                    fzprintf(sftpTransfer, "%d", rinterval);
                    rinterval = 0;
                }
            }
            len = read_from_file(file, buffer, sizeof(buffer));
            if (len == -1) {
                fzprintf(sftpError, "error while reading local file");
                err = true;
            } else if (len == 0) {
                eof = true;
            } else {
                xfer_upload_data(xfer, buffer, len);
                rinterval += len;
                if (pending_receive() >= 5)
                    break;
            }
        }

        if (toplevel_callback_pending() && !err && !eof) {
            /* If we have pending callbacks, they might make
             * xfer_upload_ready start to return true. So we should
             * run them and then re-check xfer_upload_ready, before
             * we go as far as waiting for an entire packet to
             * arrive. */
            run_toplevel_callbacks();
            continue;
        }

        if (!xfer_done(xfer)) {
            pktin = sftp_recv();
            ret = xfer_upload_gotpkt(xfer, pktin);
            if (ret <= 0) {
                if (ret == INT_MIN)        /* pktin not even freed */
                    sfree(pktin);
                if (!err) {
                    fzprintf(sftpError, "error while writing: %s", fxp_error());
                    err = true;
                }
            }
        }
    }

    if (rinterval && !err) {
        fzprintf(sftpTransfer, "%d", rinterval);
    }

    xfer_cleanup(xfer);

  cleanup:
    req = fxp_close_send(fh);
    pktin = sftp_wait_for_reply(req);
    if (!fxp_close_recv(pktin, req)) {
        if (!err) {
            fzprintf(sftpError, "error while writing: %s", fxp_error());
            err = true;
        }
    }

    close_rfile(file);

    return err ? 0 : 1;
}

/* ----------------------------------------------------------------------
 * Actual sftp commands.
 */
struct sftp_command {
    char **words;
    size_t nwords, wordssize;
    int (*obey) (struct sftp_command *);        /* returns <0 to quit */
};

int sftp_cmd_null(struct sftp_command *cmd)
{
    return 1;                          /* success */
}

int sftp_cmd_unknown(struct sftp_command *cmd)
{
    fzprintf(sftpError, "Unknown command: \"%s\"\n", cmd->words[0]);
    return 0;                          /* failure */
}

int sftp_cmd_quit(struct sftp_command *cmd)
{
    return -1;
}

int sftp_cmd_keyfile(struct sftp_command *cmd)
{
    if (cmd->nwords != 2) {
        fzprintf(sftpError, "No keyfile given");
        return 0;
    }

    conf_set_str_str(conf, CONF_fz_keyfiles, cmd->words[1], "");

    return 1;
}

int sftp_cmd_proxy(struct sftp_command *cmd)
{
    int proxy_type;
    int portnumber;

    if (cmd->nwords < 2) {
        fzprintf(sftpError, "Not enough arguments to proxy command");
        return 0;
    }

    if (!strcmp(cmd->words[1], "0")) {
        conf_set_int(conf, CONF_proxy_type, PROXY_NONE);
        return 1;
    }
    if (!strcmp(cmd->words[1], "1")) {
        proxy_type = PROXY_HTTP;
    }
    else if (!strcmp(cmd->words[1], "2")) {
        proxy_type = PROXY_SOCKS5;
    }
    else {
        fzprintf(sftpError, "Unknown proxy type");
        return 0;
    }

    if (cmd->nwords < 4) {
        fzprintf(sftpError, "Not enough arguments to proxy command");
        return 0;
    }

    portnumber = atoi(cmd->words[3]);
    if (portnumber < 0 || portnumber > 65535) {
        fzprintf(sftpError, "Invalid port");
        return 0;
    }

    if (cmd->nwords > 5) {
        conf_set_str(conf, CONF_proxy_username, cmd->words[4]);
        conf_set_str(conf, CONF_proxy_password, cmd->words[5]);
    }
    else if (cmd->nwords > 4) {
        conf_set_str(conf, CONF_proxy_username, cmd->words[4]);
        conf_set_str(conf, CONF_proxy_password, "");
    }
    else {
        conf_set_str(conf, CONF_proxy_username, "");
        conf_set_str(conf, CONF_proxy_password, "");
    }

    conf_set_int(conf, CONF_proxy_type, proxy_type);
    conf_set_str(conf, CONF_proxy_host, cmd->words[2]);
    conf_set_int(conf, CONF_proxy_port, portnumber);

    return 1;
}

int sftp_cmd_close(struct sftp_command *cmd)
{
    if (!backend) {
        not_connected();
        return 0;
    }

    if (backend_connected(backend)) {
        char ch;
        backend_special(backend, SS_EOF, 0);
        sent_eof = true;
        sftp_recvdata(&ch, 1);
    }
    do_sftp_cleanup();

    return 0;
}

/*
 * List a directory. If no arguments are given, list pwd; otherwise
 * list the directory given in words[1].
 */
int sftp_cmd_ls(struct sftp_command *cmd)
{
    struct fxp_handle *dirh;
    struct fxp_names *names;
    const char *dir;
    char *cdir;
    struct sftp_packet *pktin;
    struct sftp_request *req;
    struct sftp_request *reqs[4];
    int i;

    if (!backend) {
        not_connected();
        return 0;
    }

    if (cmd->nwords < 2)
        dir = ".";
    else
        dir = cmd->words[1];

    cdir = canonify(dir, false);
    if (!cdir) {
        fzprintf(sftpError, "%s: canonify: %s", dir, fxp_error());
        return 0;
    }

    fzprintf(sftpStatus, "Listing directory %s", cdir);

    req = fxp_opendir_send(cdir);
    pktin = sftp_wait_for_reply(req);
    dirh = fxp_opendir_recv(pktin, req);

    if (dirh == NULL) {
        fzprintf(sftpError, "Unable to open %s: %s", dir, fxp_error());
        sfree(cdir);
        return 0;
    }

    reqs[0] = fxp_readdir_send(dirh);
    reqs[1] = fxp_readdir_send(dirh);
    reqs[2] = fxp_readdir_send(dirh);
    reqs[3] = fxp_readdir_send(dirh);
    int ri = 0;
    while (1) {

        pktin = sftp_wait_for_reply(reqs[ri]);
        names = fxp_readdir_recv(pktin, reqs[ri]);
        reqs[ri] = NULL;

        if (names == NULL) {
            if (fxp_error_type() == SSH_FX_EOF)
                break;
            fzprintf(sftpError, "Reading directory %s: %s", dir, fxp_error());
            break;
        }
        if (names->nnames == 0) {
            fxp_free_names(names);
            break;
        }

        for (i = 0; i < names->nnames; i++) {
            unsigned long mtime = 0;
            if (names->names[i].attrs.flags & SSH_FILEXFER_ATTR_ACMODTIME) {
                mtime = names->names[i].attrs.mtime;
            }
            fzprintf_raw_untrusted(sftpListentry, "%s", names->names[i].longname);
            fzprintf_raw_untrusted(sftpUnknown, "%lu", mtime);
            fzprintf_raw_untrusted(sftpUnknown, "%s", names->names[i].filename);
        }

        fxp_free_names(names);
        reqs[ri++] = fxp_readdir_send(dirh);
        ri %= 4;
    }
    for (i = 0; i < 4; ++i) {
        if (reqs[ri]) {
            pktin = sftp_wait_for_reply(reqs[ri]);
            sfree(reqs[ri]);
            sfree(pktin);
        }
        ++ri;
        ri %= 4;
    }
    req = fxp_close_send(dirh);
    pktin = sftp_wait_for_reply(req);
    fxp_close_recv(pktin, req);

    sfree(cdir);

    return 1;
}

/*
 * Change directories. We do this by canonifying the new name, then
 * trying to OPENDIR it. Only if that succeeds do we set the new pwd.
 */
int sftp_cmd_cd(struct sftp_command *cmd)
{
    struct fxp_handle *dirh;
    struct sftp_packet *pktin;
    struct sftp_request *req;
    char *dir;

    if (!backend) {
        not_connected();
        return 0;
    }

    if (cmd->nwords != 2) {
        fzprintf(sftpError, "Wrong number of arguments");
        return 0;
    }

    dir = canonify(cmd->words[1], false);
    if (!dir) {
        fzprintf(sftpError, "%s: canonify: %s", cmd->words[1], fxp_error());
        return 0;
    }

    req = fxp_opendir_send(dir);
    pktin = sftp_wait_for_reply(req);
    dirh = fxp_opendir_recv(pktin, req);

    if (!dirh) {
        fzprintf(sftpError, "Directory %s: %s\n", dir, fxp_error());
        sfree(dir);
        return 0;
    }

    req = fxp_close_send(dirh);
    pktin = sftp_wait_for_reply(req);
    fxp_close_recv(pktin, req);

    sfree(pwd);
    pwd = dir;
    fzprintf(sftpReply, "New directory is: \"%s\"", pwd);

    return 1;
}

/*
 * Print current directory. Easy as pie.
 */
int sftp_cmd_pwd(struct sftp_command *cmd)
{
    if (!backend) {
        not_connected();
        return 0;
    }

    fzprintf(sftpReply, "Current directory is: \"%s\"", pwd);
    return 1;
}

/*
 * Get a file and save it at the local end. We have three very
 * similar commands here. The basic one is `get'; `reget' differs
 * in that it checks for the existence of the destination file and
 * starts from where a previous aborted transfer left off; `mget'
 * differs in that it interprets all its arguments as files to
* transfer (never as a different local name for a remote file).
 */
int sftp_general_get(struct sftp_command *cmd, int restart)
{
    char *fname, *origfname, *outfname;
    int ret;

    if (!backend) {
        not_connected();
        return 0;
    }

    if (cmd->nwords != 3) {
        fzprintf(sftpError, "%s: expects a filename", cmd->words[0]);
        return 0;
    }

    ret = 1;
    origfname = cmd->words[1];
    outfname = cmd->words[2];

    fname = canonify(origfname, false);
    if (!fname) {
        fzprintf(sftpError, "%s: canonify: %s", origfname, fxp_error());
        return 0;
    }

    ret = sftp_get_file(fname, outfname, restart);
    sfree(fname);
    return ret;
}
int sftp_cmd_get(struct sftp_command *cmd)
{
    return sftp_general_get(cmd, false);
}
int sftp_cmd_reget(struct sftp_command *cmd)
{
    return sftp_general_get(cmd, true);
}

/*
 * Send a file and store it at the remote end. We have three very
 * similar commands here. The basic one is `put'; `reput' differs
 * in that it checks for the existence of the destination file and
 * starts from where a previous aborted transfer left off; `mput'
 * differs in that it interprets all its arguments as files to
 * transfer (never as a different remote name for a local file).
 */
int sftp_general_put(struct sftp_command *cmd, int restart)
{
    char *fname, *origoutfname, *outfname;
    int ret;


    if (!backend) {
        not_connected();
        return 0;
    }

    if (cmd->nwords != 3) {
        fzprintf(sftpError, "%s: expects source and target filenames", cmd->words[0]);
        return 0;
    }
    fname = cmd->words[1];
    origoutfname = cmd->words[2];

    ret = 1;

    outfname = canonify(origoutfname, false);
    if (!outfname) {
        fzprintf(sftpError, "%s: canonify: %s", origoutfname, fxp_error());
        return 0;
    }
    ret = sftp_put_file(fname, outfname, restart);
    sfree(outfname);
    return ret;
}
int sftp_cmd_put(struct sftp_command *cmd)
{
    return sftp_general_put(cmd, false);
}
int sftp_cmd_reput(struct sftp_command *cmd)
{
    return sftp_general_put(cmd, true);
}

int sftp_cmd_mkdir(struct sftp_command *cmd)
{
    char *dir;
    struct sftp_packet *pktin;
    struct sftp_request *req;
    int result;
    int i, ret;

    if (!backend) {
        not_connected();
        return 0;
    }

    if (cmd->nwords < 2) {
        fzprintf(sftpError, "mkdir: expects a directory");
        return 0;
    }

    if (cmd->nwords > 2) {
        fzprintf(sftpError, "mkdir: too many arguments");
        return 0;
    }

    ret = 1;
    for (i = 1; i < cmd->nwords; i++) {
        dir = canonify(cmd->words[i], false);
        if (!dir) {
            fzprintf(sftpError, "%s: canonify: %s", cmd->words[i], fxp_error());
            return 0;
        }

        req = fxp_mkdir_send(dir, NULL);
        pktin = sftp_wait_for_reply(req);
        result = fxp_mkdir_recv(pktin, req);

        if (!result) {
            fzprintf(sftpError, "mkdir %s: %s", dir, fxp_error());
            ret = 0;
        } else
            fzprintf(sftpReply, "mkdir %s: OK", dir);

        sfree(dir);
    }

    return ret;
}

static int sftp_action_rmdir(char *dir)
{
    struct sftp_packet *pktin;
    struct sftp_request *req;
    int result;

    req = fxp_rmdir_send(dir);
    pktin = sftp_wait_for_reply(req);
    result = fxp_rmdir_recv(pktin, req);

    if (!result) {
        fzprintf(sftpError, "rmdir %s: %s", dir, fxp_error());
        return 0;
    }

    fzprintf(sftpReply, "rmdir %s: OK", dir);

    return 1;
}

int sftp_cmd_rmdir(struct sftp_command *cmd)
{
    if (!backend) {
        not_connected();
        return 0;
    }

    if (cmd->nwords != 2) {
        fzprintf(sftpError, "rmdir: expects a directory");
        return 0;
    }

    char * cname = canonify(cmd->words[1], false);
    if (!cname) {
        fzprintf(sftpError, "%s: canonify: %s", cmd->words[1], fxp_error());
        return 0;
    }

    int ret = sftp_action_rmdir(cname);
    sfree(cname);
    return ret;
}

static int sftp_action_rm(char *fname)
{
    struct sftp_packet *pktin;
    struct sftp_request *req;
    int result;

    req = fxp_remove_send(fname);
    pktin = sftp_wait_for_reply(req);
    result = fxp_remove_recv(pktin, req);

    if (!result) {
        fzprintf(sftpError, "rm %s: %s", fname, fxp_error());
        return 0;
    }

    fzprintf(sftpReply, "rm %s: OK", fname);

    return 1;
}

int sftp_cmd_rm(struct sftp_command *cmd)
{
    if (!backend) {
        not_connected();
        return 0;
    }

    if (cmd->nwords < 2) {
        fzprintf(sftpError, "rm: expects a filename");
        return 0;
    }

    char * cname = canonify(cmd->words[1], true);
    if (!cname) {
        fzprintf(sftpError, "%s: canonify: %s", cmd->words[1], fxp_error());
        return 0;
    }

    int ret = sftp_action_rm(cname);
    sfree(cname);
    return ret;
}

static int sftp_action_mv(char* source, char* target)
{
    struct sftp_packet *pktin;
    struct sftp_request *req;
    const char *error;
    int ret, result;

    req = fxp_rename_send(source, target);
    pktin = sftp_wait_for_reply(req);
    result = fxp_rename_recv(pktin, req);

    error = result ? NULL : fxp_error();

    if (error) {
        fzprintf(sftpError, "mv %s %s: %s", source, target, error);
        ret = 0;
    } else {
        fzprintf(sftpStatus, "%s -> %s", source, target);
        ret = 1;
    }

    return ret;
}

int sftp_cmd_mv(struct sftp_command *cmd)
{
    char *source, *target;
    int ret;

    if (!backend) {
        not_connected();
        return 0;
    }

    if (cmd->nwords != 3) {
        fzprintf(sftpError, "mv: expects two filenames");
        return 0;
    }

    source = canonify(cmd->words[1], true);
    if (!source) {
        fzprintf(sftpError, "%s: canonify: %s", cmd->words[1], fxp_error());
        return 0;
    }

    target = canonify(cmd->words[2], true);
    if (!target) {
        fzprintf(sftpError, "%s: canonify: %s", cmd->words[2], fxp_error());
        sfree(source);
        return 0;
    }

    ret = sftp_action_mv(source, target);

    sfree(source);
    sfree(target);

    return ret;
}

struct sftp_context_chmod {
    unsigned attrs_clr, attrs_xor;
};

static int sftp_action_chmod(void *vctx, char *fname)
{
    struct fxp_attrs attrs;
    struct sftp_packet *pktin;
    struct sftp_request *req;
    int result;
    unsigned oldperms, newperms;
    struct sftp_context_chmod *ctx = (struct sftp_context_chmod *)vctx;

    req = fxp_stat_send(fname);
    pktin = sftp_wait_for_reply(req);
    result = fxp_stat_recv(pktin, req, &attrs);

    if (!result || !(attrs.flags & SSH_FILEXFER_ATTR_PERMISSIONS)) {
        fzprintf(sftpError, "get attrs for %s: %s", fname,
               result ? "file permissions not provided" : fxp_error());
        return 0;
    }

    attrs.flags = SSH_FILEXFER_ATTR_PERMISSIONS;   /* perms _only_ */
    oldperms = attrs.permissions & 07777;
    attrs.permissions &= ~ctx->attrs_clr;
    attrs.permissions ^= ctx->attrs_xor;
    newperms = attrs.permissions & 07777;

    if (oldperms == newperms)
        return 1;                       /* no need to do anything! */

    req = fxp_setstat_send(fname, attrs);
    pktin = sftp_wait_for_reply(req);
    result = fxp_setstat_recv(pktin, req);

    if (!result) {
        fzprintf(sftpError, "set attrs for %s: %s", fname, fxp_error());
        return 0;
    }

    fzprintf(sftpStatus, "%s: %04o -> %04o", fname, oldperms, newperms);

    return 1;
}

int sftp_cmd_chmod(struct sftp_command *cmd)
{
    char *mode;
    struct sftp_context_chmod actx, *ctx = &actx;

    if (!backend) {
        not_connected();
        return 0;
    }

    if (cmd->nwords != 3) {
        fzprintf(sftpError, "chmod: expects a mode specifier and a filename");
        return 0;
    }

    /*
     * Attempt to parse the mode specifier in cmd->words[1]. We
     * don't support the full horror of Unix chmod; instead we
     * support a much simpler syntax in which the user can either
     * specify an octal number, or a comma-separated sequence of
     * [ugoa]*[-+=][rwxst]+. (The initial [ugoa] sequence may
     * _only_ be omitted if the only attribute mentioned is t,
     * since all others require a user/group/other specification.
     * Additionally, the s attribute may not be specified for any
     * [ugoa] specifications other than exactly u or exactly g.
     */
    ctx->attrs_clr = ctx->attrs_xor = 0;
    mode = cmd->words[1];
    if (mode[0] >= '0' && mode[0] <= '9') {
        if (mode[strspn(mode, "01234567")]) {
            fzprintf(sftpError, "chmod: numeric file modes should"
                   " contain digits 0-7 only");
            return 0;
        }
        ctx->attrs_clr = 07777;
        sscanf(mode, "%o", &ctx->attrs_xor);
        ctx->attrs_xor &= ctx->attrs_clr;
    } else {
        while (*mode) {
            char *modebegin = mode;
            unsigned subset, perms;
            int action;

            subset = 0;
            while (*mode && *mode != ',' &&
                   *mode != '+' && *mode != '-' && *mode != '=') {
                switch (*mode) {
                  case 'u': subset |= 04700; break; /* setuid, user perms */
                  case 'g': subset |= 02070; break; /* setgid, group perms */
                  case 'o': subset |= 00007; break; /* just other perms */
                  case 'a': subset |= 06777; break; /* all of the above */
                  default:
                    fzprintf(sftpError, "chmod: file mode '%.*s' contains unrecognised"
                           " user/group/other specifier '%c'",
                           (int)strcspn(modebegin, ","), modebegin, *mode);
                    return 0;
                }
                mode++;
            }
            if (!*mode || *mode == ',') {
                fzprintf(sftpError, "chmod: file mode '%.*s' is incomplete",
                       (int)strcspn(modebegin, ","), modebegin);
                return 0;
            }
            action = *mode++;
            if (!*mode || *mode == ',') {
                fzprintf(sftpError, "chmod: file mode '%.*s' is incomplete",
                       (int)strcspn(modebegin, ","), modebegin);
                return 0;
            }
            perms = 0;
            while (*mode && *mode != ',') {
                switch (*mode) {
                  case 'r': perms |= 00444; break;
                  case 'w': perms |= 00222; break;
                  case 'x': perms |= 00111; break;
                  case 't': perms |= 01000; subset |= 01000; break;
                  case 's':
                    if ((subset & 06777) != 04700 &&
                        (subset & 06777) != 02070) {
                        fzprintf(sftpError, "chmod: file mode '%.*s': set[ug]id bit should"
                               " be used with exactly one of u or g only",
                               (int)strcspn(modebegin, ","), modebegin);
                        return 0;
                    }
                    perms |= 06000;
                    break;
                  default:
                    fzprintf(sftpError, "chmod: file mode '%.*s' contains unrecognised"
                           " permission specifier '%c'",
                           (int)strcspn(modebegin, ","), modebegin, *mode);
                    return 0;
                }
                mode++;
            }
            if (!(subset & 06777) && (perms &~ subset)) {
                fzprintf(sftpError, "chmod: file mode '%.*s' contains no user/group/other"
                       " specifier and permissions other than 't'",
                       (int)strcspn(modebegin, ","), modebegin);
                return 0;
            }
            perms &= subset;
            switch (action) {
              case '+':
                ctx->attrs_clr |= perms;
                ctx->attrs_xor |= perms;
                break;
              case '-':
                ctx->attrs_clr |= perms;
                ctx->attrs_xor &= ~perms;
                break;
              case '=':
                ctx->attrs_clr |= subset;
                ctx->attrs_xor |= perms;
                break;
            }
            if (*mode) mode++;         /* eat comma */
        }
    }


    char * cname = canonify(cmd->words[2], false);
    if (!cname) {
        fzprintf(sftpError, "%s: canonify: %s", cmd->words[2], fxp_error());
        return 0;
    }

    sftp_action_chmod(ctx, cname);
    sfree(cname);
    return 0;
}

static int sftp_cmd_chmtime(struct sftp_command *cmd)
{
    char *p;
    uint64_t mtime = 0;

    if (!backend) {
        not_connected();
        return 0;
    }

    if (cmd->nwords != 3) {
        fzprintf(sftpError, "chmtime: expects the time and a filename");
        return 0;
    }

    char *cname = canonify(cmd->words[2], false);
    if (!cname) {
        fzprintf(sftpError, "%s: canonify: %s", cmd->words[2], fxp_error());
        return 0;
    }

    // Make sure mtime is valid
    p = cmd->words[1];
    while (*p) {
        char c = *p++;
        if (c < '0' || c > '9') {
            fzprintf(sftpError, "chmtime: not a valid time");
            sfree(cname);
            return 0;
        }
        mtime *= 10;
        mtime += c - '0';
    }

    struct fxp_attrs attrs = {0};
    struct sftp_packet* pktin;
    struct sftp_request* req;

    attrs.flags = SSH_FILEXFER_ATTR_ACMODTIME;

    req = fxp_stat_send(cname);
    pktin = sftp_wait_for_reply(req);
    int result = fxp_stat_recv(pktin, req, &attrs);

    if (!result || !(attrs.flags & SSH_FILEXFER_ATTR_ACMODTIME)) {
        fzprintf(sftpError, "get attrs for %s: %s", cname,
             result ? "times not provided" : fxp_error());
        sfree(cname);
        return 0;
    }

    attrs.flags = SSH_FILEXFER_ATTR_ACMODTIME;

    if (attrs.mtime == mtime) {
        fzprintf(sftpVerbose, "Keeping existing mtime");
        sfree(cname);
        return 1;
    }
    attrs.mtime = mtime;

    req = fxp_setstat_send(cname, attrs);
    pktin = sftp_wait_for_reply(req);
    result = fxp_setstat_recv(pktin, req);

    if (!result) {
        fzprintf(sftpError, "set attrs for %s: %s", cname, fxp_error());
        sfree(cname);
        return 0;
    }

    sfree(cname);

    return 1;
}

static int sftp_cmd_mtime(struct sftp_command *cmd)
{
    char *filename, *cname;
    int result;
    uint64_t mtime;
    struct fxp_attrs attrs = {0};
    struct sftp_packet *pktin;
    struct sftp_request *req;

    if (!backend) {
        not_connected();
        return 0;
    }

    if (cmd->nwords != 2) {
        fzprintf(sftpError, "mtime: expects exactly one filename as argument");
        return 0;
    }

    filename = cmd->words[1];

    cname = canonify(filename, false);
    if (!cname) {
        fzprintf(sftpError, "%s: canonify: %s", filename, fxp_error());
        return 0;
    }
    attrs.flags = SSH_FILEXFER_ATTR_ACMODTIME;
    req = fxp_stat_send(cname);
    pktin = sftp_wait_for_reply(req);
    result = fxp_stat_recv(pktin, req, &attrs);

    if (!result) {
        fzprintf(sftpError, "get attrs for %s: %s", cname,
               fxp_error());

        sfree(cname);
        return 0;
    }

    attrs.flags &= SSH_FILEXFER_ATTR_ACMODTIME;

    if (attrs.flags & SSH_FILEXFER_ATTR_ACMODTIME) {
        mtime = attrs.mtime;
    }
    else {
        fzprintf(sftpError, "get attrs for %s: %s", cname,
               "mtime not provided");
        sfree(cname);
        return 0;
    }

    sfree(cname);

    fzprintf(sftpReply, "%"PRIu64, mtime);
    return 1;
}

static int sftp_cmd_open(struct sftp_command *cmd)
{
    int portnumber;

    if (backend) {
        fzprintf(sftpError, "psftp: already connected");
        return 0;
    }

    if (cmd->nwords < 2) {
        fzprintf(sftpError, "open: expects a host name");
        return 0;
    }

    if (cmd->nwords > 2) {
        portnumber = atoi(cmd->words[2]);
        if (portnumber == 0) {
            fzprintf(sftpError, "open: invalid port number");
            return 0;
        }
    } else
        portnumber = 0;

    if (psftp_connect(cmd->words[1], NULL, portnumber)) {
        backend = NULL;                /* connection is already closed */
        return -1;                     /* this is fatal */
    }
    if (do_sftp_init()) {
        cleanup_exit(1);
    }
    fznotify1(sftpDone, 1);
    return 1;
}

static struct sftp_cmd_lookup {
    const char *name;
    int (*obey) (struct sftp_command *);
} sftp_lookup[] = {
    /*
     * List of sftp commands. This is binary-searched so it MUST be
     * in ASCII order.
     */
    {
        "bye", sftp_cmd_quit
    },
    {
        "cd", sftp_cmd_cd
    },
    {
        "chmod", sftp_cmd_chmod
    },
    {
        "chmtime", sftp_cmd_chmtime
    },
    {
        "close", sftp_cmd_close
    },
    {
        "del", sftp_cmd_rm
    },
    {
        "delete", sftp_cmd_rm
    },
    {
        "exit", sftp_cmd_quit
    },
    {
        "get", sftp_cmd_get
    },
    {
        "keyfile", sftp_cmd_keyfile
    },

    {
        "ls", sftp_cmd_ls
    },
    {
        "mkdir", sftp_cmd_mkdir
    },
    {
        "mtime", sftp_cmd_mtime
    },
    {
        "mv", sftp_cmd_mv
    },
    {
        "open", sftp_cmd_open
    },
    {
        "proxy", sftp_cmd_proxy
    },
    {
        "put", sftp_cmd_put
    },
    {
        "pwd", sftp_cmd_pwd
    },
    {
        "quit", sftp_cmd_quit
    },
    {
        "reget", sftp_cmd_reget
    },
    {
        "reput", sftp_cmd_reput
    },
    {
        "rm", sftp_cmd_rm
    },
    {
        "rmdir", sftp_cmd_rmdir
    }
};

const struct sftp_cmd_lookup *lookup_command(const char *name)
{
    int i, j, k, cmp;

    i = -1;
    j = lenof(sftp_lookup);
    while (j - i > 1) {
        k = (j + i) / 2;
        cmp = strcmp(name, sftp_lookup[k].name);
        if (cmp < 0)
            j = k;
        else if (cmp > 0)
            i = k;
        else {
            return &sftp_lookup[k];
        }
    }
    return NULL;
}

/* ----------------------------------------------------------------------
 * Command line reading and parsing.
 */
struct sftp_command *sftp_getcmd()
{
    char *line;
    struct sftp_command *cmd;
    char *p, *q, *r;
    bool quoting;

    cmd = snew(struct sftp_command);
    cmd->words = NULL;
    cmd->nwords = 0;
    cmd->wordssize = 0;

    line = ssh_sftp_get_cmdline("psftp> ", !backend);

    if (!line || !*line) {
        cmd->obey = sftp_cmd_quit;
        sfree(line);
        return cmd;                       /* eof */
    }

    line[strcspn(line, "\r\n")] = '\0';

    p = line;
    while (*p && (*p == ' ' || *p == '\t'))
        p++;

    if (*p == '!') {
        /*
         * Special case: the ! command. This is always parsed as
         * exactly two words: one containing the !, and the second
         * containing everything else on the line.
         */
        cmd->nwords = 2;
        sgrowarrayn(cmd->words, cmd->wordssize, cmd->nwords, 0);
        cmd->words[0] = dupstr("!");
        cmd->words[1] = dupstr(p+1);
    } else if (*p == '#') {
        /*
         * Special case: comment. Entire line is ignored.
         */
        cmd->nwords = cmd->wordssize = 0;
    } else {

        /*
         * Parse the command line into words. The syntax is:
         *  - double quotes are removed, but cause spaces within to be
         *    treated as non-separating.
         *  - a double-doublequote pair is a literal double quote, inside
         *    _or_ outside quotes. Like this:
         *
         *      firstword "second word" "this has ""quotes"" in" and""this""
         *
         * becomes
         *
         *      >firstword<
         *      >second word<
         *      >this has "quotes" in<
         *      >and"this"<
         */
        while (1) {
            /* skip whitespace */
            while (*p && (*p == ' ' || *p == '\t'))
                p++;
            /* terminate loop */
            if (!*p)
                break;
            /* mark start of word */
            q = r = p;                 /* q sits at start, r writes word */
            quoting = false;
            while (*p) {
                if (!quoting && (*p == ' ' || *p == '\t'))
                    break;                     /* reached end of word */
                else if (*p == '"' && p[1] == '"')
                    p += 2, *r++ = '"';    /* a literal quote */
                else if (*p == '"')
                    p++, quoting = !quoting;
                else
                    *r++ = *p++;
            }
            if (*p)
                p++;                   /* skip over the whitespace */
            *r = '\0';
            sgrowarray(cmd->words, cmd->wordssize, cmd->nwords);
            cmd->words[cmd->nwords++] = dupstr(q);
        }
    }

    sfree(line);

    /*
     * Now parse the first word and assign a function.
     */

    if (cmd->nwords == 0)
        cmd->obey = sftp_cmd_null;
    else {
        const struct sftp_cmd_lookup *lookup;
        lookup = lookup_command(cmd->words[0]);
        if (!lookup)
            cmd->obey = sftp_cmd_unknown;
        else
            cmd->obey = lookup->obey;
    }

    return cmd;
}

static void sftp_cmd_free(struct sftp_command *cmd)
{
    if (cmd->words) {
        for (size_t i = 0; i < cmd->nwords; i++)
            sfree(cmd->words[i]);
        sfree(cmd->words);
    }
    sfree(cmd);
}

static int do_sftp_init(void)
{
    struct sftp_packet *pktin;
    struct sftp_request *req;

    /*
     * Do protocol initialisation.
     */
    if (!fxp_init()) {
        fzprintf(sftpError,
                "Fatal: unable to initialise SFTP on server: %s\n", fxp_error());
        return 1;                      /* failure */
    }

    /*
     * Find out where our home directory is.
     */
    req = fxp_realpath_send(".");
    pktin = sftp_wait_for_reply(req);
    homedir = fxp_realpath_recv(pktin, req);

    if (!homedir) {
        fzprintf(sftpError,
                "Warning: failed to resolve home directory: %s\n",
                fxp_error());
        homedir = dupstr(".");
    } else {
        fzprintf(sftpVerbose,
            "Remote working directory is %s", homedir);
    }
    pwd = dupstr(homedir);
    return 0;
}

static void do_sftp_cleanup(void)
{
    char ch;
    if (backend) {
        backend_special(backend, SS_EOF, 0);
        sent_eof = true;
        sftp_recvdata(&ch, 1);
        backend_free(backend);
        sftp_cleanup_request();
        backend = NULL;
    }
    if (pwd) {
        sfree(pwd);
        pwd = NULL;
    }
    if (homedir) {
        sfree(homedir);
        homedir = NULL;
    }
}

int do_sftp()
{
    int ret;

    /* ------------------------------------------------------------------
        * Now we're ready to do Real Stuff.
        */
    while (1) {
        struct sftp_command *cmd;
        cmd = sftp_getcmd();
        if (!cmd)
            break;
        pending_reply = true;
        ret = cmd->obey(cmd);
        sftp_cmd_free(cmd);
        if (pending_reply) {
            fznotify1(sftpDone, ret);
        }
        if (ret < 0)
            break;
    }
    return 0;
}

/* ----------------------------------------------------------------------
 * Dirty bits: integration with PuTTY.
 */

static bool verbose = false;

void ldisc_echoedit_update(Ldisc *ldisc) { }

/*
 * Receive a block of data from the SSH link. Block until all data
 * is available.
 *
 * To do this, we repeatedly call the SSH protocol module, with our
 * own psftp_output() function to catch the data that comes back. We
 * do this until we have enough data.
 */
static bufchain received_data;
static BinarySink *stderr_bs;
static size_t psftp_output(
    Seat *seat, bool is_stderr, const void *data, size_t len)
{
    /*
     * stderr data is just spouted to local stderr (optionally via a
     * sanitiser) and otherwise ignored.
     */
    if (is_stderr) {
        put_data(stderr_bs, data, len);
        return 0;
    }

    bufchain_add(&received_data, data, len);
    return 0;
}

static bool psftp_eof(Seat *seat)
{
    /*
     * We expect to be the party deciding when to close the
     * connection, so if we see EOF before we sent it ourselves, we
     * should panic.
     */
    if (!sent_eof) {
        seat_connection_fatal(
            psftp_seat, "Received unexpected end-of-file from SFTP server");
    }
    return false;
}

bool sftp_recvdata(char *buf, size_t len)
{
    while (len > 0) {
        while (bufchain_size(&received_data) == 0) {
            if (backend_exitcode(backend) >= 0 ||
                ssh_sftp_loop_iteration() < 0)
                return false;          /* doom */
        }

        size_t got = bufchain_fetch_consume_up_to(&received_data, buf, len);
        buf += got;
        len -= got;
    }

    return true;
}
bool sftp_senddata(const char *buf, size_t len)
{
    backend_send(backend, buf, len);
    return true;
}
size_t sftp_sendbuffer(void)
{
    return backend_sendbuffer(backend);
}

/*
 *  Short description of parameters.
 */
static void usage(void)
{
    printf("Not meant for human consumption. Use FileZilla instead.\n");
    cleanup_exit(1);
}

static void version(void)
{
  char *buildinfo_text = buildinfo("\n");
  printf("psftp: %s\n%s\n", ver, buildinfo_text);
  sfree(buildinfo_text);
  exit(0);
}

/*
 * Connect to a host.
 */
static int psftp_connect(char *userhost, char *user, int portnumber)
{
    char *host, *realhost;
    const char *err;

    /* Separate host and username */
    host = userhost;
    host = strrchr(host, '@');
    if (host == NULL) {
        host = userhost;
    } else {
        *host++ = '\0';
        if (user) {
            fzprintf(sftpVerbose, "psftp: multiple usernames specified; using \"%s\"",
                   user);
        } else
            user = userhost;
    }

    /*
     * If we haven't loaded session details already (e.g., from -load),
     * try looking for a session called "host".
     */
    if (!cmdline_loaded_session()) {
        /* Try to load settings for `host' into a temporary config */
        Conf *conf2 = conf_new();
        conf_set_str(conf2, CONF_host, "");
        do_defaults(host, conf2);
        if (conf_get_str(conf2, CONF_host)[0] != '\0') {
            fzprintf(sftpVerbose, "psftp: Implicit session load.");
            /* Settings present and include hostname */
            /* Re-load data into the real config. */
            do_defaults(host, conf);
        } else {
            /* Session doesn't exist or mention a hostname. */
            /* Use `host' as a bare hostname. */
            conf_set_str(conf, CONF_host, host);
        }
        conf_free(conf2);
    } else {
        fzprintf(sftpVerbose, "psftp: Using previously loaded session.");
        /* Patch in hostname `host' to session details. */
        conf_set_str(conf, CONF_host, host);
    }

    /*
     * Force protocol to SSH if the user has somehow contrived to
     * select one we don't support (e.g. by loading an inappropriate
     * saved session). In that situation we assume the port number is
     * useless too.)
     */
    if (!backend_vt_from_proto(conf_get_int(conf, CONF_protocol))) {
        conf_set_int(conf, CONF_protocol, PROT_SSH);
        conf_set_int(conf, CONF_port, 22);
    }

    /* FZ: Require SSH2 */
    conf_set_int(conf, CONF_sshprot, 3);

    /*
     * Enact command-line overrides.
     */
    cmdline_run_saved(conf);

    /*
     * Muck about with the hostname in various ways.
     */
    {
        char *hostbuf = dupstr(conf_get_str(conf, CONF_host));
        char *host = hostbuf;
        char *p, *q;

        /*
         * Trim leading whitespace.
         */
        host += strspn(host, " \t");

        /*
         * See if host is of the form user@host, and separate out
         * the username if so.
         */
        if (host[0] != '\0') {
            char *atsign = strrchr(host, '@');
            if (atsign) {
                *atsign = '\0';
                conf_set_str(conf, CONF_username, host);
                host = atsign + 1;
            }
        }

        /*
         * Remove any remaining whitespace.
         */
        p = hostbuf;
        q = host;
        while (*q) {
            if (*q != ' ' && *q != '\t')
                *p++ = *q;
            q++;
        }
        *p = '\0';

        conf_set_str(conf, CONF_host, hostbuf);
        sfree(hostbuf);
    }

    /* Set username */
    if (user != NULL && user[0] != '\0') {
        conf_set_str(conf, CONF_username, user);
    }
    if (!conf_get_str(conf, CONF_username) || !*conf_get_str(conf, CONF_username)) {
        // Original psftp allows this though. But FZ always provides a username.
        fzprintf(sftpError, "psftp: no username, aborting");
        cleanup_exit(1);
    }

    if (portnumber)
        conf_set_int(conf, CONF_port, portnumber);

    /* fz: we always need a mainchan */
    conf_set_bool(conf, CONF_ssh_no_shell, false);

    /*
     * Disable scary things which shouldn't be enabled for simple
     * things like SCP and SFTP: agent forwarding, port forwarding,
     * X forwarding.
     */
    conf_set_bool(conf, CONF_x11_forward, false);
    conf_set_bool(conf, CONF_agentfwd, false);
    conf_set_bool(conf, CONF_ssh_simple, true);
    {
        char *key;
        while ((key = conf_get_str_nthstrkey(conf, CONF_portfwd, 0)) != NULL)
            conf_del_str_str(conf, CONF_portfwd, key);
    }

    /* Set up subsystem name. */
    conf_set_str(conf, CONF_remote_cmd, "sftp");
    conf_set_bool(conf, CONF_ssh_subsys, true);
    conf_set_bool(conf, CONF_nopty, true);

    /*
     * Set up fallback option, for SSH-1 servers or servers with the
     * sftp subsystem not enabled but the server binary installed
     * in the usual place. We only support fallback on Unix
     * systems, and we use a kludgy piece of shellery which should
     * try to find sftp-server in various places (the obvious
     * systemwide spots /usr/lib and /usr/local/lib, and then the
     * user's PATH) and finally give up.
     *
     *   test -x /usr/lib/sftp-server && exec /usr/lib/sftp-server
     *   test -x /usr/local/lib/sftp-server && exec /usr/local/lib/sftp-server
     *   exec sftp-server
     *
     * the idea being that this will attempt to use either of the
     * obvious pathnames and then give up, and when it does give up
     * it will print the preferred pathname in the error messages.
     */
    conf_set_str(conf, CONF_remote_cmd2,
                 "test -x /usr/lib/sftp-server &&"
                 " exec /usr/lib/sftp-server\n"
                 "test -x /usr/local/lib/sftp-server &&"
                 " exec /usr/local/lib/sftp-server\n"
                 "exec sftp-server");
    conf_set_bool(conf, CONF_ssh_subsys2, false);

    psftp_logctx = log_init(console_cli_logpolicy, conf);

    platform_psftp_pre_conn_setup(console_cli_logpolicy);

    err = backend_init(backend_vt_from_proto(
                           conf_get_int(conf, CONF_protocol)),
                       psftp_seat, &backend, psftp_logctx, conf,
                       conf_get_str(conf, CONF_host),
                       conf_get_int(conf, CONF_port),
                       &realhost, 0,
                       conf_get_bool(conf, CONF_tcp_keepalives));
    if (err != NULL) {
        fzprintf(sftpError, "ssh_init: %s", err);
        return 1;
    }
    while (!backend_sendok(backend)) {
        if (backend_exitcode(backend) >= 0)
            return 1;
        if (ssh_sftp_loop_iteration() < 0) {
            fzprintf(sftpError, "ssh_init: error during SSH connection setup");
            return 1;
        }
    }
    if (verbose && realhost != NULL)
        fzprintf(sftpStatus, "Connected to %s", realhost);
    if (realhost != NULL)
        sfree(realhost);
    return 0;
}

void cmdline_error(const char *p, ...)
{
    char *str;
    va_list ap;

    va_start(ap, p);
    str = dupvprintf(p, ap);
    va_end(ap);
    fzprintf(sftpError, "psftp: %s", str);
    sfree(str);

    exit(1);
}

#ifndef _WINDOWS

static const char * const utf8suffixes[] = { ".utf8", ".utf-8", ".UTF8", ".UTF-8", "" };

int psftp_init_utf8_locale()
{
    unsigned int i;
    char* locale = setlocale(LC_CTYPE, "");
    if (locale)
    {
        if (strcmp(locale, "C") && strcmp(locale, "POSIX"))
        {
            char *lang, *mod, *utf8locale;
            char *s;
            unsigned int i;

            for (i = 0; utf8suffixes[i]; i++)
                if (strstr(locale, utf8suffixes[i]))
                    return 0;

            // Locale is of the form 
            //   language[_territory][.code-set][@modifier]
            // Insert utf8 locale 
            lang = dupstr(locale);

            s = strchr(lang, '.');
            if (!s)
                s = strchr(lang, '@');
            if (s)
                *s = 0;

            s = strchr(locale, '@');
            if (s)
                mod = dupstr(s);
            else
                mod = dupstr("");

            for (i = 0; *utf8suffixes[i]; i++)
            {
                utf8locale = dupprintf("%s%s%s", lang, utf8suffixes[i], mod);
                
                locale = setlocale(LC_CTYPE, utf8locale);
                sfree(utf8locale);
                if (!locale)
                {
                    utf8locale = dupprintf("%s%s", lang, utf8suffixes[i]);
                    locale = setlocale(LC_CTYPE, utf8locale);
                    sfree(utf8locale);
                }

                if (locale)
                {
                    sfree(lang);
                    sfree(mod);
                    return 0;
                }
            }
            sfree(lang);
            sfree(mod);
        }
    }

    // Try a few common locales
    for (i = 0; *utf8suffixes[i]; i++)
    {
        char* utf8locale;

        utf8locale = dupprintf("en_US%s", utf8suffixes[i]);
        locale = setlocale(LC_CTYPE, utf8locale);
        sfree(utf8locale);
        if (locale)
            return 0;

        utf8locale = dupprintf("en_GB%s", utf8suffixes[i]);
        locale = setlocale(LC_CTYPE, utf8locale);
        sfree(utf8locale);
        if (locale)
            return 0;
    }

    // Fallback to C locale
    setlocale(LC_CTYPE, "C");
    return 1;
}
#endif

const bool share_can_be_downstream = false; // FZ: We're standalone
const bool share_can_be_upstream = false;

static stdio_sink stderr_ss;
static StripCtrlChars *stderr_scc;

const unsigned cmdline_tooltype = TOOLTYPE_FILETRANSFER;

/*
 * Main program. Parse arguments etc.
 */
#if defined(__MINGW32__)
__declspec(dllexport) // This forces ld to not strip relocations so that ASLR can work on MSW.
#endif
int psftp_main(int argc, char *argv[])
{
    int i, ret;
    int portnumber = 0;
    char *userhost, *user;
    bool sanitise_stderr = true;

    fzprintf(sftpReply, "fzSftp started, protocol_version=%d", FZSFTP_PROTOCOL_VERSION);

#ifndef _WINDOWS
    if (psftp_init_utf8_locale())
        fzprintf(sftpVerbose, "Failed to select UTF-8 locale, filenames containing non-US-ASCII characters may cause problems.");
#endif

    sk_init();

    userhost = user = NULL;

    /* Load Default Settings before doing anything else. */
    conf = conf_new();
    do_defaults(NULL, conf);

    conf_set_bool(conf, CONF_change_username, false);

    // FZ: Set proxy to none
    conf_set_int(conf, CONF_proxy_type, PROXY_NONE);

    // FZ: Re-order ciphers so that old and insecure algorithms are always below the warning level
    {
        // Find position of warning level
        int warn = -1;
        for (i = 0; i < CIPHER_MAX && warn == -1; ++i) {
            int cipher = conf_get_int_int(conf, CONF_ssh_cipherlist, i);
            if (cipher == CIPHER_WARN) {
                warn = i;
            }
        }

        if (warn != -1 && warn < CIPHER_MAX) {
            for (i = warn - 1; i >= 0; --i) {
                int const cipher = conf_get_int_int(conf, CONF_ssh_cipherlist, i);
                if (cipher == CIPHER_ARCFOUR || cipher == CIPHER_DES) {
                    int j;
                    // Bubble it down
                    for (j = i; j < warn; ++j) {
                        int swap = conf_get_int_int(conf, CONF_ssh_cipherlist, j + 1);
                        conf_set_int_int(conf, CONF_ssh_cipherlist, j, swap);
                    }
                    conf_set_int_int(conf, CONF_ssh_cipherlist, warn, cipher);
                    --warn;
                }
            }
        }
    }

    for (i = 1; i < argc; i++) {
        int ret;
        if (argv[i][0] != '-') {
            if (userhost)
                usage();
            else
                userhost = dupstr(argv[i]);
            continue;
        }
        ret = cmdline_process_param(argv[i], i+1<argc?argv[i+1]:NULL, 1, conf);
        if (ret == -2) {
            cmdline_error("option \"%s\" requires an argument", argv[i]);
        } else if (ret == 2) {
            i++;               /* skip next argument */
        } else if (ret == 1) {
            /* We have our own verbosity in addition to `flags'. */
            if (cmdline_verbose())
                verbose = true;
        } else if (strcmp(argv[i], "-V") == 0 ||
                   strcmp(argv[i], "--version") == 0) {
            version();
        } else if (strcmp(argv[i], "--") == 0) {
            i++;
            break;
        } else {
            cmdline_error("unknown option \"%s\"", argv[i]);
        }
    }
    argc -= i;
    argv += i;
    backend = NULL;

    stdio_sink_init(&stderr_ss, stderr);
    stderr_bs = BinarySink_UPCAST(&stderr_ss);
    if (sanitise_stderr) {
        stderr_scc = stripctrl_new(stderr_bs, false, L'\0');
        stderr_bs = BinarySink_UPCAST(stderr_scc);
    }

    string_scc = stripctrl_new(NULL, false, L'\0');

    /*
     * If the loaded session provides a hostname, and a hostname has not
     * otherwise been specified, pop it in `userhost' so that
     * `psftp -load sessname' is sufficient to start a session.
     */
    /* BEGIN FZ UNUSED
    if (!userhost && conf_get_str(conf, CONF_host)[0] != '\0') {
        userhost = dupstr(conf_get_str(conf, CONF_host));
    }
    END FZ UNUSED */

    /*
     * If a user@host string has already been provided, connect to
     * it now.
     */
    if (userhost) {
        int ret;

        fzprintf(sftpVerbose, "psftp: Using userhost passed on commandline: %s", userhost);
        ret = psftp_connect(userhost, user, portnumber);
        sfree(userhost);
        if (ret)
            return 1;
        if (do_sftp_init())
            return 1;
    }

    ret = do_sftp();

    if (backend && backend_connected(backend)) {
        char ch;
        backend_special(backend, SS_EOF, 0);
        sent_eof = true;
        sftp_recvdata(&ch, 1);
    }
    do_sftp_cleanup();
    random_save_seed();
    cmdline_cleanup();
    sk_cleanup();

    stripctrl_free(string_scc);
    stripctrl_free(stderr_scc);

    if (psftp_logctx)
        log_free(psftp_logctx);

    return ret;
}
