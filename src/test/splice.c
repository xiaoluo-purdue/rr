/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define TOKEN "ABC"
#define TOKEN_SIZE sizeof(TOKEN)

static const char token_file[] = "/tmp/rr-splice-file.txt";

void verify_token(int fd) {
	ssize_t len;
	char buf[TOKEN_SIZE];

	len = read(fd, buf, sizeof(buf));
	if (len != TOKEN_SIZE || strcmp(buf, TOKEN)) {
		puts("Internal error: FAILED: splice wrote the wrong data");
		exit(1);
	}
	puts("Got expected token " TOKEN);
}

int main() {
	int pipefds[2];
	int filefd;
	loff_t off;

	filefd = open(token_file, O_RDWR | O_CREAT | O_TRUNC, 0600);
	pipe2(pipefds, 0/*no flags*/);
	write(pipefds[1], TOKEN, TOKEN_SIZE);

	splice(pipefds[0], NULL, filefd, NULL, TOKEN_SIZE, 0/*no flags*/);

	lseek(filefd, 0, SEEK_SET);
	verify_token(filefd);

	off = 0;
	splice(filefd, &off, pipefds[1], NULL, TOKEN_SIZE, 0/*no flags*/);

	verify_token(pipefds[0]);

	/* The test driver will clean up after us if the test failed
	 * before this. */
	unlink(token_file);

	return 0;
}
