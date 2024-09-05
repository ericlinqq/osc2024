#include "vfs.h"

struct mount *rootfs;

int register_filesystem(struct filesystem *fs)
{
  // TODO:
  // register the file system to the kernel.
  // you can also initialize memory pool of the file system here.

}

int vfs_open(const char *pathname, int flags, struct file **target)
{
  // TODO:
  // 1. Lookup pathname
  // 2. Create a new file handle for this vnode if found.
  // 3. Create a new file if O_CREAT is specified in flags and vnode not found
  // lookup error code shows if file exist or not or other error occurs
  // 4. Return error code if fails

}

int vfs_close(struct file *file)
{
  // TODO:
  // 1. release the file handle
  // 2. Return error code if fails
}

int vfs_write(struct file *file, const void *buf, size_t len)
{
  // TODO:
  // 1. write len bytes from buf to the opened file.
  // 2. return written size or error code if an error occurs.
}

int vfs_read(struct file *file, void *buf, size_t len)
{
  // TODO:
  // 1. read min(len, readable size) byte to buf from the opened file.
  // 2. block if nothing to read for FIFO type.
  // 3. return read size or error code if an error occurs.
}
