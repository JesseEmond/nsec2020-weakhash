// This is the challenge itself.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>

#include <unistd.h>

#include <openssl/des.h>

/*
 * Password hash algorithm:
 *
 *  - Input is a character string in printable ASCII (codes 32 to 126,
 *    inclusive).
 *
 *  - Each character is encoded into a byte by multiplying its value by
 *    two, then adding two (e.g. 'A' is ASCII 65, encoded as byte of value
 *    65*2 + 2 = 132).
 *    (This encoding is because the low bit of each byte is ignored when
 *    used in a DES key.)
 *
 *  - Between 0 and 7 bytes of value 0x00 are appended, so that total
 *    length in bytes is a multiple of 8.
 *
 *  - Padded sequence is split into blocks of 8 bytes: M_1, M_2,... M_n.
 *
 *  - Eight-byte value V is initialized to the ASCII encoding of the
 *    "weakhash" string: 77 65 61 6B 68 61 73 68
 *
 *  - V is encrypted with DES, using M_1 as key. The output is then
 *    encrypted again with DES, using M_2 as key. And so on. The final
 *    value (output of encryption with M_n as key) is the hash output
 *    (64 bits).
 *
 * Test vector: hash of "Hello World" (an 11-character string) is:
 *   F31506471220CD8F
 */

/*
 * Apply WeakHash on password 'src'. Output is written in dst[] (8 bytes).
 */
void
weakhash(uint8_t *dst, const char *src)
{
	DES_key_schedule ks;
	DES_cblock key;
	DES_cblock data;
	size_t u, n;

	memcpy(data, "weakhash", 8);
	n = strlen(src);
	for (u = 0; u < n; u += 8) {
		size_t v;

		for (v = 0; v < 8; v ++) {
			if (u + v < n) {
				key[v] = ((unsigned char)src[u + v] << 1) + 2;
			} else {
				key[v] = 0;
			}
		}
		DES_set_key_unchecked(&key, &ks);
		DES_ecb_encrypt(&data, &data, &ks, 1);
	}
	memcpy(dst, data, 8);
}

/*
 * Send an error message.
 */
static void
send_errmsg(int errcode, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	printf("Status: %03d Failed\n", errcode);
	printf("Content-Type: text/html; charset=UTF-8\n");
	printf("\n");
	printf("<html>\n");
	printf("<body>\n");
	vfprintf(stdout, fmt, ap);
	printf("<p><a href=\"javascript:history.back()\">Back...</a></p>\n");
	printf("</body>\n");
	printf("</html>\n");
	va_end(ap);
}

/*
 * Print a string, escaping all required characters for clean HTML output.
 */
static void
print_htmlesc(const char *text)
{
	const uint8_t *buf;

	buf = (const uint8_t *)text;
	for (;;) {
		uint32_t x;

		x = *buf ++;
		if (x == 0) {
			return;
		}
		if (x >= 128) {
			int n;

			if (x < 0xC0) {
				x = 0xFFFD;
				n = 0;
			} else if (x < 0xE0) {
				x &= 0x1F;
				n = 1;
			} else if (x < 0xF0) {
				x &= 0x0F;
				n = 2;
			} else if (x < 0xF8) {
				x &= 0x07;
				n = 3;
			} else {
				x = 0xFFFD;
				n = 0;
			}
			while (n -- > 0) {
				uint32_t y;

				y = *buf ++;
				if (y >= 0x80 && y < 0xC0) {
					x = (x << 6) | (y & 0x3F);
				} else if (y == 0) {
					return;
				} else {
					x = 0xFFFD;
					break;
				}
			}
		}

		if (x >= 32 && x <= 126 && x != '<' && x != '>' && x != '&') {
			putchar((int)x);
		} else {
			printf("&x%X;", x);
		}
	}
}

/*
 * Send an error message translating a system error code.
 */
static void
send_system_error(const char *text, int err)
{
	printf("Status: 500 Failed\n");
	printf("Content-Type: text/html; charset=UTF-8\n");
	printf("\n");
	printf("<html>\n");
	printf("<body>\n");
	printf("<p>");
	print_htmlesc(text);
	printf(": errno = %d: ", err);
	print_htmlesc(strerror(err));
	printf("</p>\n");
	printf("<p><a href=\"javascript:history.back()\">Back...</a></p>\n");
	printf("</body>\n");
	printf("</html>\n");
}

static inline int
hexval(int c)
{
	if (c >= '0' && c <= '9') {
		return c - '0';
	} else if (c >= 'A' && c <= 'F') {
		return c - ('A' - 10);
	} else if (c >= 'a' && c <= 'f') {
		return c - ('a' - 10);
	} else {
		return -1;
	}
}

/*
 * Find a parameter in a query string. If found, then value is written
 * (with URL decoding) into the provided output buffer, and
 * zero-terminated.
 * On input, *buf_len contains the buffer size; at most *buf_len bytes
 * will be written in buf[] (including the terminating zero).
 * On output, *buf_len is set to the number of bytes written in buf[],
 * _excluding_ the terminating 0.
 *
 * Parameter name is provided in 'name' and must have the exact same
 * value as found in the query string (no URL-decoding is done for the
 * parameter name). If the parameter is found but has no value (or an
 * empty value), then a success is returned.
 *
 * Returned value: 1 on success, 0 on error. An error is reported if the
 * parameter is not found, or is not properly URL-encoded, or is larger
 * than can fit in the buffer.
 */
static int
find_param(uint8_t *buf, size_t *buf_len, const char *qs, const char *name)
{
	const char *p;
	size_t name_len, u, lim;

	if (*buf_len == 0) {
		return 0;
	}
	p = qs;
	name_len = strlen(name);
	for (;;) {
		const char *q;

		q = p;
		while (*q != 0 && *q != '=' && *q != '&') {
			q ++;
		}
		if ((size_t)(q - p) == name_len
			&& memcmp(name, p, name_len) == 0)
		{
			if (*q != '=') {
				buf[0] = 0;
				*buf_len = 0;
				return 1;
			}
			p = q + 1;
			break;
		}
		while (*q != 0 && *q != '&') {
			q ++;
		}
		if (!*q) {
			return 0;
		}
		p = q + 1;
	}

	/*
	 * p points to the value.
	 */
	u = 0;
	lim = *buf_len - 1;
	for (;;) {
		int c;

		c = *p ++;
		if (c == 0 || c == '&') {
			buf[u] = 0;
			*buf_len = u;
			return 1;
		}
		if (c == '%') {
			int c0, c1;

			c0 = hexval(*p ++);
			if (c0 < 0) {
				return 0;
			}
			c1 = hexval(*p ++);
			if (c1 < 0) {
				return 0;
			}
			c = c0 * 16 + c1;
		}
		if (u >= lim) {
			return 0;
		}
		buf[u ++] = (uint8_t)c;
	}
}

static int
hv_eq(const uint8_t *hv1, const uint8_t *hv2)
{
	int i, s;

	s = 0;
	for (i = 0; i < 8; i ++) {
		s |= hv1[i] ^ hv2[i];
	}
	return s == 0;
}

static int
is_alphanum(const uint8_t *src)
{
	for (;;) {
		int c;

		c = *src ++;
		if (c == 0) {
			return 1;
		}
		if (c >= '0' && c <= '9') {
			continue;
		}
		if (c >= 'A' && c <= 'Z') {
			continue;
		}
		if (c >= 'a' && c <= 'z') {
			continue;
		}
		return 0;
	}
}

/*
 * CGI-bin interface.
 */
int
main(void)
{
	char *qs, fname[100];
	uint32_t rr[2];
	uint8_t password[100];
	uint8_t uid[50];
	uint8_t mark[30];
	size_t password_len, uid_len, mark_len;
	uint8_t hv[8];
	int err, found;
	FILE *f, *g;

	static const uint8_t ref_hv1[8] = {
		0xDA, 0x99, 0xD1, 0xEA, 0x64, 0x14, 0x4F, 0x3E
	};
	static const uint8_t ref_hv2[8] = {
		0x59, 0xA3, 0x44, 0x2D, 0x8B, 0xAB, 0xCF, 0x84
	};

	qs = getenv("QUERY_STRING");
	if (qs == NULL) {
		send_errmsg(401, "<p>No query string</p>\n");
		return 0;
	}
	password_len = sizeof password;
	if (!find_param(password, &password_len, qs, "password")) {
		send_errmsg(401, "<p>No password provided.</p>\n");
		return 0;
	}
	uid_len = sizeof uid;
	if (!find_param(uid, &uid_len, qs, "uid")) {
		send_errmsg(401, "<p>No user ID provided.</p>\n");
		return 0;
	}
	mark_len = sizeof mark;
	if (!find_param(mark, &mark_len, qs, "mark")) {
		send_errmsg(401, "<p>No mark provided.</p>\n");
		return 0;
	}

	/*
	 * The UID and the mark should contain only alphanumeric characters.
	 */
	if (!is_alphanum(uid)) {
		send_errmsg(401, "<p>UID is not alphanumeric.</p>\n");
		return 0;
	}
	if (!is_alphanum(mark)) {
		send_errmsg(401, "<p>Mark is not alphanumeric.</p>\n");
		return 0;
	}

	weakhash(hv, (char *)password);
	if (!hv_eq(hv, ref_hv1) && !hv_eq(hv, ref_hv2)) {
		send_errmsg(401, "<p>Wrong password.</p>\n");
		return 0;
	}

	/*
	 * Password is OK, change the mark for the specified UID.
	 */
	 char cwd[1024];
	f = fopen("/tmp/marks.txt", "r");
	if (f == NULL) {
		send_system_error("fopen() (read)", errno);
		return 0;
	}
	if (getentropy((void *)rr, sizeof rr) < 0) {
		send_system_error("getentropy()", errno);
		return 0;
	}
	sprintf(fname, "/tmp/marks-%08x%08x.txt", rr[0], rr[1]);
	g = fopen(fname, "w");
	if (g == NULL) {
		send_system_error("fopen() (write)", errno);
		fclose(f);
		return 0;
	}
	err = 0;
	found = 0;
	for (;;) {
		char line[512];
		size_t n;

		if (fgets(line, sizeof line, f) == NULL) {
			if (ferror(f)) {
				err = errno;
			}
			goto loop_exit;
		}
		n = strlen(line);
		if (n >= (sizeof line) - 1) {
			/*
			 * Line is very long, skip it.
			 */
			for (;;) {
				if (fputs(line, g) < 0) {
					err = errno;
					goto loop_exit;
				}
				if (line[n - 1] == '\n') {
					break;
				}
				if (fgets(line, sizeof line, f) == NULL) {
					if (ferror(f)) {
						err = errno;
					}
					goto loop_exit;
				}
				n = strlen(line);
				if (n == 0) {
					break;
				}
			}
		} else {
			if (n > uid_len && line[uid_len] == ','
				&& memcmp(uid, line, uid_len) == 0)
			{
				found = 1;
				if (fprintf(g, "%s,%s\n", uid, mark) < 0) {
					err = errno;
					goto loop_exit;
				}
			} else {
				if (fputs(line, g) < 0) {
					err = errno;
					goto loop_exit;
				}
			}
		}
	}

loop_exit:
	fclose(f);
	if (err == 0 && !found) {
		if (fprintf(g, "%s,%s\n", uid, mark) < 0) {
			err = errno;
		}
	}
	if (fclose(g) < 0) {
		if (err == 0) {
			err = errno;
		}
	}
	if (err != 0) {
		remove(fname);
		send_system_error("I/O error", err);
		return 0;
	}

	/*if (rename(fname, "/tmp/marks.txt") < 0) {
		send_system_error("rename()", errno);
		remove(fname);
		return 0;
	}*/

	printf("Content-Type: text/html; charset=UTF-8\n");
	printf("\n");
	printf("<html>\n");
	printf("<body>\n");
	printf("<p>Success: ");
	if (found) {
		printf("changed mark of %s to %s", uid, mark);
	} else {
		printf("added new UID %s with mark %s", uid, mark);
	}
	printf(".</p>\n");
	printf("<p><a href=\"../index.html\">Back...</a></p>\n");
	printf("</body>\n");
	printf("</html>\n");
	return 0;
}
