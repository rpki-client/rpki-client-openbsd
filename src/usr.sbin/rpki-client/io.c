/*	$OpenBSD: io.c,v 1.26 2024/11/21 13:32:27 claudio Exp $ */
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

	if ((b = ibuf_dynamic(64, MAX_MSG_SIZE)) == NULL)
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

	len = ibuf_size(b);
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

ssize_t
io_parse_hdr(struct ibuf *b, void *arg)
{
	size_t s;

	if (ibuf_get(b, &s, sizeof(s)) == -1)
		return -1;
	if (s > MAX_MSG_SIZE) {
		errno = ERANGE;
		return -1;
	}
	return s;
}

struct ibuf *
io_buf_get(struct msgbuf *msgq)
{
	struct ibuf *b;

	if ((b = msgbuf_get(msgq)) == NULL)
		return NULL;

	ibuf_skip(b, sizeof(size_t));
	return b;
}
