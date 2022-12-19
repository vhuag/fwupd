/*
 * Copyright (C) 2012 Andrew Duggan
 * Copyright (C) 2012 Synaptics Inc.
 * Copyright (C) 2019 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include <glib-object.h>

#define RMI_PRODUCT_ID_LENGTH	  10
#define RMI_DEVICE_PDT_ENTRY_SIZE 6

typedef struct {
	guint16 query_base;
	guint16 command_base;
	guint16 control_base;
	guint16 data_base;
	guint8 interrupt_source_count;
	guint8 function_number;
	guint8 function_version;
	guint8 interrupt_reg_num;
	guint8 interrupt_mask;
} FuSynapticsRmiFunction;

guint32
fu_synaptics_rmi_generate_checksum(const guint8 *data, gsize len);
FuSynapticsRmiFunction *
fu_synaptics_rmi_function_parse(GByteArray *buf,
				guint16 page_base,
				guint interrupt_count,
				GError **error);
gboolean
fu_synaptics_rmi_device_writeln(const gchar *fn, const gchar *buf, GError **error);
gboolean
fu_synaptics_verify_sha256_signature(GBytes *payload,
				     GBytes *pubkey,
				     GBytes *signature,
				     GError **error);


const gchar * pszEngineerRSAPublicKey3k = "\
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


const gchar * pszEngineerRSAPublicKey2k = "\
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

const gchar* pszProductionKey[4] = {
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
             

