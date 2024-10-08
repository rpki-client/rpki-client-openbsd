/*	$OpenBSD: io.c,v 1.25 2024/08/28 09:39:17 tb Exp $ */
/*
 * Copyright (c) 2021 Claudio Jeker <claudio@openbsd.org>
 * Copyright (c) 2019 Kristaps Dzonsons <kristaps@bsd.lv>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/queue.h>
#include <sys/socket.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <imsg.h>

#include "extern.h"

/*
 * Create new io buffer, call io_close() when done with it.
 * Function always returns a new buffer.
 */
struct ibuf *
io_new_buffer(void)
{
	struct ibuf *b;

	if ((b = ibuf_dynamic(64, INT32_MAX)) == NULL)
		err(1, NULL);
	ibuf_add_zero(b, sizeof(size_t));	/* can not fail */
	return b;
}

/*
 * Add a simple object of static size to the io buffer.
 */
void
io_simple_buffer(struct ibuf *b, const void *res, size_t sz)
{
	if (ibuf_add(b, res, sz) == -1)
		err(1, NULL);
}

/*
 * Add a sz sized buffer into the io buffer.
 */
void
io_buf_buffer(struct ibuf *b, const void *p, size_t sz)
{
	if (ibuf_add(b, &sz, sizeof(size_t)) == -1)
		err(1, NULL);
	if (sz > 0)
		if (ibuf_add(b, p, sz) == -1)
			err(1, NULL);
}

/*
 * Add a string into the io buffer.
 */
void
io_str_buffer(struct ibuf *b, const char *p)
{
	size_t sz = (p == NULL) ? 0 : strlen(p);

	io_buf_buffer(b, p, sz);
}

/*
 * Finish and enqueue a io buffer.
 */
void
io_close_buffer(struct msgbuf *msgbuf, struct ibuf *b)
{
	size_t len;

	len = ibuf_size(b) - sizeof(len);
	ibuf_set(b, 0, &len, sizeof(len));
	ibuf_close(msgbuf, b);
}

/*
 * Read of an ibuf and extract sz byte from there.
 * Does nothing if "sz" is zero.
 * Return 1 on success or 0 if there was not enough data.
 */
void
io_read_buf(struct ibuf *b, void *res, size_t sz)
{
	if (sz == 0)
		return;
	if (ibuf_get(b, res, sz) == -1)
		err(1, "bad internal framing");
}

/*
 * Read a string (returns NULL for zero-length strings), allocating
 * space for it.
 * Return 1 on success or 0 if there was not enough data.
 */
void
io_read_str(struct ibuf *b, char **res)
{
	size_t	 sz;

	io_read_buf(b, &sz, sizeof(sz));
	if (sz == 0) {
		*res = NULL;
		return;
	}
	if ((*res = calloc(sz + 1, 1)) == NULL)
		err(1, NULL);
	io_read_buf(b, *res, sz);
}

/*
 * Read a binary buffer, allocating space for it.
 * If the buffer is zero-sized, this won't allocate "res", but
 * will still initialise it to NULL.
 * Return 1 on success or 0 if there was not enough data.
 */
void
io_read_buf_alloc(struct ibuf *b, void **res, size_t *sz)
{
	*res = NULL;
	io_read_buf(b, sz, sizeof(*sz));
	if (*sz == 0)
		return;
	if ((*res = malloc(*sz)) == NULL)
		err(1, NULL);
	io_read_buf(b, *res, *sz);
}

/* XXX copy from imsg-buffer.c */
static int
ibuf_realloc(struct ibuf *buf, size_t len)
{
	unsigned char	*b;

	/* on static buffers max is eq size and so the following fails */
	if (len > SIZE_MAX - buf->wpos || buf->wpos + len > buf->max) {
		errno = ERANGE;
		return (-1);
	}

	b = realloc(buf->buf, buf->wpos + len);
	if (b == NULL)
		return (-1);
	memset(b + buf->size, 0, buf->wpos + len - buf->size);
	buf->buf = b;
	buf->size = buf->wpos + len;

	return (0);
}

/*
 * Read once and fill a ibuf until it is finished.
 * Returns NULL if more data is needed, returns a full ibuf once
 * all data is received.
 */
struct ibuf *
io_buf_read(int fd, struct ibuf **ib)
{
	struct ibuf *b = *ib;
	ssize_t n;
	size_t sz;

	/* if ibuf == NULL allocate a new buffer */
	if (b == NULL) {
		if ((b = ibuf_dynamic(sizeof(sz), INT32_MAX)) == NULL)
			err(1, NULL);
		*ib = b;
	}

 again:
	/* read some data */
	while ((n = read(fd, b->buf + b->wpos, b->size - b->wpos)) == -1) {
		if (errno == EINTR)
			continue;
		if (errno == EAGAIN)
			return NULL;
		err(1, "read");
	}

	if (n == 0)
		errx(1, "read: unexpected end of file");
	b->wpos += n;

	/* got full message */
	if (b->wpos == b->size) {
		/* only header received */
		if (b->wpos == sizeof(sz)) {
			memcpy(&sz, b->buf, sizeof(sz));
			if (sz == 0 || sz > INT32_MAX)
				errx(1, "bad internal framing, bad size");
			if (ibuf_realloc(b, sz) == -1)
				err(1, "ibuf_realloc");
			goto again;
		}

		/* skip over initial size header */
		b->rpos += sizeof(sz);
		*ib = NULL;
		return b;
	}

	return NULL;
}

/*
 * Read data from socket but receive a file descriptor at the same time.
 */
struct ibuf *
io_buf_recvfd(int fd, struct ibuf **ib)
{
	struct ibuf *b = *ib;
	struct iovec iov;
	struct msghdr msg;
	struct cmsghdr *cmsg;
	union {
		struct cmsghdr	hdr;
		char		buf[CMSG_SPACE(sizeof(int))];
	} cmsgbuf;
	ssize_t n;
	size_t sz;

	/* fd are only passed on the head, just use regular read afterwards */
	if (b != NULL)
		return io_buf_read(fd, ib);

	if ((b = ibuf_dynamic(sizeof(sz), INT32_MAX)) == NULL)
		err(1, NULL);
	*ib = b;

	memset(&msg, 0, sizeof(msg));
	memset(&cmsgbuf, 0, sizeof(cmsgbuf));

	iov.iov_base = b->buf;
	iov.iov_len = b->size;

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = &cmsgbuf.buf;
	msg.msg_controllen = sizeof(cmsgbuf.buf);

	while ((n = recvmsg(fd, &msg, 0)) == -1) {
		if (errno == EINTR)
			continue;
		err(1, "recvmsg");
	}

	if (n == 0)
		errx(1, "recvmsg: unexpected end of file");

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
	    cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level == SOL_SOCKET &&
		    cmsg->cmsg_type == SCM_RIGHTS) {
			int i, j, f;

			j = ((char *)cmsg + cmsg->cmsg_len -
			    (char *)CMSG_DATA(cmsg)) / sizeof(int);
			for (i = 0; i < j; i++) {
				f = ((int *)CMSG_DATA(cmsg))[i];
				if (i == 0)
					ibuf_fd_set(b, f);
				else
					close(f);
			}
		}
	}

	b->wpos += n;

	/* got full message */
	if (b->wpos == b->size) {
		/* only header received */
		if (b->wpos == sizeof(sz)) {
			memcpy(&sz, b->buf, sizeof(sz));
			if (sz == 0 || sz > INT32_MAX)
				errx(1, "read: bad internal framing, %zu", sz);
			if (ibuf_realloc(b, sz) == -1)
				err(1, "ibuf_realloc");
			return NULL;
		}

		/* skip over initial size header */
		b->rpos += sizeof(sz);
		*ib = NULL;
		return b;
	}

	return NULL;
}
