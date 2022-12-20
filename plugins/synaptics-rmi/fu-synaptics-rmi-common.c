/*
 * Copyright (C) 2012 Andrew Duggan
 * Copyright (C) 2012 Synaptics Inc.
 * Copyright (C) 2019 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include <fwupdplugin.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifdef HAVE_GNUTLS
#include <gnutls/abstract.h>
#include <gnutls/crypto.h>
#endif

#include "fu-synaptics-rmi-common.h"

#define RMI_FUNCTION_QUERY_OFFSET	      0
#define RMI_FUNCTION_COMMAND_OFFSET	      1
#define RMI_FUNCTION_CONTROL_OFFSET	      2
#define RMI_FUNCTION_DATA_OFFSET	      3
#define RMI_FUNCTION_INTERRUPT_SOURCES_OFFSET 4
#define RMI_FUNCTION_NUMBER		      5

#define RMI_FUNCTION_VERSION_MASK	    0x60
#define RMI_FUNCTION_INTERRUPT_SOURCES_MASK 0x7

#ifdef HAVE_GNUTLS
typedef guchar gnutls_data_t;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"
G_DEFINE_AUTOPTR_CLEANUP_FUNC(gnutls_data_t, gnutls_free)
G_DEFINE_AUTO_CLEANUP_FREE_FUNC(gnutls_pubkey_t, gnutls_pubkey_deinit, NULL)
#pragma clang diagnostic pop
#endif

guint32
fu_synaptics_rmi_generate_checksum(const guint8 *data, gsize len)
{
	guint32 lsw = 0xffff;
	guint32 msw = 0xffff;
	for (gsize i = 0; i < len / 2; i++) {
		lsw += fu_memread_uint16(&data[i * 2], G_LITTLE_ENDIAN);
		msw += lsw;
		lsw = (lsw & 0xffff) + (lsw >> 16);
		msw = (msw & 0xffff) + (msw >> 16);
	}
	return msw << 16 | lsw;
}

FuSynapticsRmiFunction *
fu_synaptics_rmi_function_parse(GByteArray *buf,
				guint16 page_base,
				guint interrupt_count,
				GError **error)
{
	FuSynapticsRmiFunction *func;
	guint8 interrupt_offset;
	const guint8 *data = buf->data;

	/* not expected */
	if (buf->len != RMI_DEVICE_PDT_ENTRY_SIZE) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INTERNAL,
			    "PDT entry buffer invalid size %u != %i",
			    buf->len,
			    RMI_DEVICE_PDT_ENTRY_SIZE);
		return NULL;
	}

	func = g_new0(FuSynapticsRmiFunction, 1);
	func->query_base = data[RMI_FUNCTION_QUERY_OFFSET] + page_base;
	func->command_base = data[RMI_FUNCTION_COMMAND_OFFSET] + page_base;
	func->control_base = data[RMI_FUNCTION_CONTROL_OFFSET] + page_base;
	func->data_base = data[RMI_FUNCTION_DATA_OFFSET] + page_base;
	func->interrupt_source_count =
	    data[RMI_FUNCTION_INTERRUPT_SOURCES_OFFSET] & RMI_FUNCTION_INTERRUPT_SOURCES_MASK;
	func->function_number = data[RMI_FUNCTION_NUMBER];
	func->function_version =
	    (data[RMI_FUNCTION_INTERRUPT_SOURCES_OFFSET] & RMI_FUNCTION_VERSION_MASK) >> 5;
	if (func->interrupt_source_count > 0) {
		func->interrupt_reg_num = (interrupt_count + 8) / 8 - 1;
		/* set an enable bit for each data source */
		interrupt_offset = interrupt_count % 8;
		func->interrupt_mask = 0;
		for (guint i = interrupt_offset;
		     i < (func->interrupt_source_count + interrupt_offset);
		     i++)
			func->interrupt_mask |= 1 << i;
	}
	return func;
}

gboolean
fu_synaptics_rmi_device_writeln(const gchar *fn, const gchar *buf, GError **error)
{
	int fd;
	g_autoptr(FuIOChannel) io = NULL;

	fd = open(fn, O_WRONLY);
	if (fd < 0) {
		g_set_error(error, FWUPD_ERROR, FWUPD_ERROR_INVALID_FILE, "could not open %s", fn);
		return FALSE;
	}
	io = fu_io_channel_unix_new(fd);
	return fu_io_channel_write_raw(io,
				       (const guint8 *)buf,
				       strlen(buf),
				       1000,
				       FU_IO_CHANNEL_FLAG_NONE,
				       error);
}

gboolean
fu_synaptics_verify_sha256_signature(GBytes *payload,
				     GBytes *pubkey,
				     GBytes *signature,
				     GError **error)
{
#ifdef HAVE_GNUTLS
	gnutls_datum_t hash;
	gnutls_datum_t m;
	gnutls_datum_t e;
	gnutls_datum_t sig;
	gnutls_hash_hd_t sha2;
	g_auto(gnutls_pubkey_t) pub = NULL;
	gint ec;
	guint8 exponent[] = {1, 0, 1};
	guint hash_length = gnutls_hash_get_len(GNUTLS_DIG_SHA256);
	g_autoptr(gnutls_data_t) hash_data = NULL;

	/* hash firmware data */
	hash_data = gnutls_malloc(hash_length);
	gnutls_hash_init(&sha2, GNUTLS_DIG_SHA256);
	gnutls_hash(sha2, g_bytes_get_data(payload, NULL), g_bytes_get_size(payload));
	gnutls_hash_deinit(sha2, hash_data);

	/* hash */
	hash.size = hash_length;
	hash.data = hash_data;

	/* modulus */
	m.size = g_bytes_get_size(pubkey);
	m.data = (guint8 *)g_bytes_get_data(pubkey, NULL);

	/* exponent */
	e.size = sizeof(exponent);
	e.data = exponent;

	/* signature */
	sig.size = g_bytes_get_size(signature);
	sig.data = (guint8 *)g_bytes_get_data(signature, NULL);

	gnutls_pubkey_init(&pub);
	ec = gnutls_pubkey_import_rsa_raw(pub, &m, &e);
	if (ec < 0) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_NOT_SUPPORTED,
			    "failed to import RSA key: %s",
			    gnutls_strerror(ec));
		return FALSE;
	}
	ec = gnutls_pubkey_verify_hash2(pub, GNUTLS_SIGN_RSA_SHA256, 0, &hash, &sig);
	if (ec < 0) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_NOT_SUPPORTED,
			    "failed to verify firmware: %s",
			    gnutls_strerror(ec));
		return FALSE;
	}
#endif
	/* success */
	return TRUE;
}

const gchar pszEngineerRSAPublicKey3k[] = "\
-----BEGIN PUBLIC KEY-----\n\
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAyhaj18TgLfCgYd6yXWi4\n\
2kHUYtsbqL4fveMp8+hMLExuqiKU11pBoGgVNqkCQ9RXnc5wolMDKYvItDvPSNJj\n\
Ip0l2voM11oAQWXAPy6TIAVOZTshRMYbzVfrecdeUCyojmgVpKTmUBLRKLVcayXz\n\
Uoq2OjIEZluqF8FwRzK2tkPe8bVhNMVO/dE8Jptgu/j6bdQbmSzvZPY8btz5Bvlo\n\
sccMKVkWtdnMGoEmiv5VfjEwY7PxosEIqZPqG8wpMvzjppwGMG2htwQLrIGoKeRp\n\
Gq4cZmAIMS5wvdHcL+AY7t8IP77mZz7OzzlQk+uYtyAktplcPvCFFd6rhwAjZTfl\n\
gOpw0hI7fCIA0lSRL+TATmKiSlYu5vLtkg/KOH7ItaY20/dyXTLJ7+8wkEwNyRfP\n\
X2Nitg1fpYbHguNjTIKnLyKioXVxwNi3mMIj1ZISJSqUY9koULSQGmavNwKjHYpX\n\
wpsloqbdBKIXQC7gTUUpEerWXn4HDtVRm3qAz3A/bXKRAgMBAAE=\n\
-----END PUBLIC KEY-----\
";


const gchar pszEngineerRSAPublicKey2k[] = "\
-----BEGIN PUBLIC KEY-----\n\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAony7196aeitgE0SU5NPz\n\
fro6XeKR7Z3yB4WAQ+YlXXLz/qZ0KmbaTHhb36aiBUWg2Z6emGztBC/fTJQ8WTz6\n\
9Nolp2+ydic8NgDGTrja2h4x/2VmATf7TtZ0tqRZIEAzn+5Arg9uPKrKseTkIu1X\n\
ieuu87r/yUC4qhVLTk7STUaUw0sE9zxA1v4YrHXNI43FLKQbX4PwkEoImpP5hcnr\n\
bDy/lLrO0TFS/Vh3QquTedrLCjnGgwBqLRkuBcRvSE0d0OCIZH7hdqEe6f+lq3wj\n\
PJMika7Ndyh6HZAoAgD1bLnqbi38WK4Z7LEZZ2LF/BZZuQOp+SzFHDJlV1mIQzNb\n\
6wIDAQAB\n\
-----END PUBLIC KEY-----\
";

const char pszProductionKey2[][] = {
"\
-----BEGIN PUBLIC KEY-----\n\
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAum0B1Y+kTcuIakI4OkRE\n\
Bf40ADir8I+jli9zMDYVvD7gAC8L6FSdfdMY/2AkJFZc7DHq9C09+Nxh9zyO6R4O\n\
dBILndcTjxZFGdwA8hNzjBkeQo+8s1Ec+Ahku/BOJM31AUmocHAhyzSM+CFzfUfX\n\
aX2u4KjvQZL/OR6mFPOOVH0fj91j/CP5pm29/W2Jz61sMDCA2iku1VD75kHR73GV\n\
mYh6CYvQzvr/BMvudrzvDlsMeK67PMd7Xj7pLEusEW3j4hVy6gj6uCXrbhb9MJU5\n\
6n181iJm1ybLSFsBRr78wMS6uM60fWLpdrs+pLe3c5EQiZ5UYi5LHxe/kCZ39bGc\n\
qeR1VOWp+it5tHSUcNsWVzYaM2ty18ICXlW9f/dMIQPBFBg16SwOm4uAWSeDRCrq\n\
vBNZmwx8boByJ1QO2z/r2sQXqzX2Car5QzSxaW0UVapIzOacPkyr/9sG7wlbJ8hu\n\
g5h2UtWXUJu/vButayrJ8aVQXhbRQKBECHmkylAlHovJAgMBAAE=\n\
-----END PUBLIC KEY-----\
",
"\
-----BEGIN PUBLIC KEY-----\n\
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAx0QXs+t4dlMHCEA0ISnf\n\
EONaRIpf99NQl1H3+Ajz6Z5HVScx2uOrd7HaWT0LTvnWl4ELvdqf9Bl+sySZDsrv\n\
HiP5ar61l3DXpa2BfaGqx0l2wY/Z+A9wDXjg+Bo+urXD00ovfZAB0iWNNsW9Qe8Z\n\
5a1RZSKuTSXXKUfG2hfyCA3m22P8YCyw3N4n8FhBqbRVMfgFCIyKAFJ+0CrH3F0k\n\
yMJ6Eq1pDqWPzI+YvmAS0kW87md2Ykc4djG7JPymFbyo6IbAuvWfM7bLO/dasEQj\n\
wKZHZbtyiE9zC/GDECsj/Aw9F3obFFVAWGX2ISnzKeMKBoDoKVDFql57T8E6lZju\n\
9hOtAK8Yq/yGfFvxTOOX2HqkuPiU6WMnzJpDIeejmoOouAO3pW99IC6Kbvruoy0q\n\
0uOvEbfjeT5c3JlgHqIfacgw0FnnGSR15hwBM7TFrA4XH/vxJygRaaoCzH7FWqmo\n\
ZBmkelvvgIZKwBdrlHgfpcUZteU8yCLrqhXTzNqAkPfzAgMBAAE=\n\
-----END PUBLIC KEY-----\
",
"\
-----BEGIN PUBLIC KEY-----\n\
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA3yUbNEx4f2btSZlQ23kY\n\
odg/ggClo5xMZo16vbTjHq4qYQO59+UFGb3X9WnFAUQPmh3EvuXNrA/lYghLEf6G\n\
L51ktwM2Hs2krBQp+3gk/yY0XW6O3uMe88jebnbIiajG+Ee2a2PsQVcc4dSdtRvx\n\
EOupZKUXIUqll8pgZccYHhvOOLgZu7qdxXnjS84SNRMry1nV6aWAkP5YStAaE3T3\n\
R/KvlfOiXHQSuthUrQPm7y2mw1S/TQIjVlW985bXU69aycLKzIg4Sz2lObwajBU6\n\
WOq0kKrg3NDabctZobjihJxC9eey6dwrzFRoPREBPup+XzBVbEBN4Wsd932XYksx\n\
R1vopLwRyXc0/RKIJC7y9jxaNwkqTQEv7zWM423oCWhiyfrso27Cjv4Lx/UbBwlW\n\
AKbnTj+HV20cQ938vhWEB3+pEEEleb+ln8/UKmQ+XjhUbkrymnuUn6QG+h4F3jQJ\n\
b8XZrLBvq+3Gtk7qD6SNX19P4ktFgl+Y7HS5EqCrXl99AgMBAAE= \n\
----- END PUBLIC KEY-----\
",
"\
-----BEGIN PUBLIC KEY-----\n\
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAyRmBwRXN0qEF1jWWhHYL\n\
qUS/C2KV2wH5IVPSwWTrdizOl03u+FtaebNYgxJlGZ69nYjkqYUAcdMES7hCJ9Bs\n\
wiM7ErEMJyLzlm70gtCTOOweIVnqUayK0dOdntSavITvLTt+9QcLIElmVn5o7Mp2\n\
y7i0p5Kc97Jriiv3omgTucIu+T7beRfpqQvmOHcnlf2cgwv+AElpJe8hvIK8YRuQ\n\
Y2wfSV6B2tqAyF/SJdXWi6DEVcFnd5IgHtp079QZBB7Zx1UQQQ4VT0437F+vcj/F\n\
ZLh3KS5/PcVaLl9nk/RMNnMhlG8K8iLg+Eg/dyds11sfrMsUwGwOKAyoXa6o+UQ7\n\
WYjF6QAvN6Mi5mi1V/VBRke5lAP1WR1ZnYKv0XgsRmsA43guUVHUQcPIZ1LZ4UG0\n\
SM8dyUPAXnMUE1Bn2hzKTGn7Bhm3/eXebnE5p/0PoxN4mWsK+jcxZMCFNd/Ab7IN\n\
SCOCJ7suL9kutd5nmFriYDWCemRnPUOTEShjN2xqf6ktAgMBAAE=\n\
-----END PUBLIC KEY-----\
"
};

