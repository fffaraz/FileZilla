# FileZilla AppImage

This is an unofficial fork of FileZilla, mirrored from the project's official Subversion repository.

A build script has been added that compiles FileZilla inside a Docker container and produces a portable AppImage executable.

## What's changed

The maximum number of simultaneous connections has been increased from 10 to 99.
This patch exists because the original maintainer refused to make this change — see [ticket #5062](https://trac.filezilla-project.org/ticket/5062) and [this forum thread](https://forum.filezilla-project.org/viewtopic.php?t=51699) for context.

## Building

To compile FileZilla inside a Docker container and produce an AppImage executable, simply run:

```sh
./build.sh
./FileZilla.AppImage
```
