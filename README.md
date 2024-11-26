# CS 118 Fall 24 Project 2

This repository contains the solution to Project 1. It also has extra code that serves as the baseline to Project 2.

`security.c` and `security.h` are wrappers around OpenSSL 3's `libcrypto` library. Any of the complicated cryptography mechanics have already been implemented for you. Feel free to read their descriptions in `security.h`. When submitting, make sure to add these files to your Makefile and your ZIP file.

In the `keys` directory, you'll see the files mentioned by the spec. Place these in the current working directory of wherever you're testing. For example, if you run `./client` and your PWD is `/Users/eado`, make sure `ca_public_key.bin` exists in `/Users/eado`. Note that the autograder automatically generates these files--do not rely on the exact contents of them. Read the [spec](https://docs.google.com/document/d/1FmEiFnYRwgBep5xgdoXmsTbzCaiUmznaYc6W-SHPtCs) for more info.
