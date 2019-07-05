This is a sample program that uses fuse_mt , mapping all zip to cbz ,rar to cbr
if you have lots zip/rar and want to use them with ubooquity (which only supports
cbz/cbr extension), this will be useful.

To use it and test fuse_mt, run:

    cargo run <path to filesystem> <mount point>

Unmount it with `fusermount -u <mount point>` or kill pid from pid file

came from fuse_mt example
