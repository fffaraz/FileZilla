#ifndef LIBFILEZILLA_GLUE_UNIX_HEADER
#define LIBFILEZILLA_GLUE_UNIX_HEADER

/** \file
 * \brief Platform specific glue for Unix(-like) platforms, including macOS.
 */

#include "../libfilezilla.hpp"

#ifndef FZ_WINDOWS

namespace fz {

/**
 * \brief Sets FD_CLOEXEC on file descriptor
 *
 * If you use this function, you probably also want to use \ref fz::forkblock
 */
bool FZ_PUBLIC_SYMBOL set_cloexec(int fd);

/**
 * \brief Creates a pipe with FD_CLOEXEC set
 *
 * If present uses pipe2 so it's set atomically, falls
 * back to fcntl.
 *
 * On failure sets fds to -1.
 */
bool FZ_PUBLIC_SYMBOL create_pipe(int fds[2]);

/** \brief Disables SIGPIPE
 *
 * \note This is implicitly called by create_pipe and when a socket is created.
 */
void FZ_PUBLIC_SYMBOL disable_sigpipe();

/// Creates a connected pair of unix domain sockets of SOCK_STREAM type
bool FZ_PUBLIC_SYMBOL create_socketpair(int fds[2]);

/** Sends file descriptors over a Unix Domain Socket.
 *
 * fd may be -1.
 * If fd is not -1, the buffer must not be empty.
 *
 * Returns the amount of bytes sent, which may be less than requested, or -1 on error.
 *
 * If any bytes got sent then the descriptor has been sent as well.
 *
 * If having sent an fd, you should not send any other fd until the buffer has been completely
 * sent.
 *
 * The data you sent should be structured such that the receiving end can detect which
 * parts of data in the stream have a descriptor associated with it.
 */
int FZ_PUBLIC_SYMBOL send_fd(int socket, fz::buffer & buf, int fd, int & error);

/** Reads data and file descriptors from a Unix Domain Socket
 *
 * Appends any read data to the buffer, returns the number of bytes added.
 *
 * Returns 0 on EOF, -1 on error.
 *
 * If a descriptor got read, it is returned in the fd argument. If no descriptor got read,
 * fd is set to -1.
 */
int FZ_PUBLIC_SYMBOL read_fd(int socket, fz::buffer & buf, int &fd, int & error);

/// Returns 0 on success, errno otherwise
int FZ_PUBLIC_SYMBOL set_nonblocking(int fd, bool non_blocking = true);

}

#else
#error This file is not for Windows
#endif

#endif
