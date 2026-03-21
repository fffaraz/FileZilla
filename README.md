# FileZilla

This is a fork of FileZilla, mirrored from the project's official Subversion repository.

## What's changed

The maximum number of simultaneous connections has been increased from 10 to 50.
This patch exists because the original maintainer refused to make this change — see [ticket #5062](https://trac.filezilla-project.org/ticket/5062) for context.

Also a dockerized build script (`build.sh`) has been added that compiles FileZilla inside a Docker container and produces a portable AppImage executable.

## Building

To compile FileZilla inside a Docker container and produce an AppImage executable, simply run:

```sh
./build.sh
./FileZilla.AppImage
```
