/*
 * Copyright (C) 2019 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include "fu-tpm-eventlog-common.h"
#include "fu-tpm-eventlog-device.h"
#include "fu-plugin-vfuncs.h"
#include "fu-hash.h"

void
fu_plugin_init (FuPlugin *plugin)
{
	fu_plugin_set_build_hash (plugin, FU_BUILD_HASH);
	fu_plugin_set_device_gtype (plugin, FU_TYPE_TPM_EVENTLOG_DEVICE);
}

gboolean
fu_plugin_coldplug (FuPlugin *plugin, GError **error)
{
	const gchar *fn = "/sys/kernel/security/tpm0/binary_bios_measurements";
	gsize bufsz = 0;
	g_autofree guint8 *buf = NULL;
	g_autoptr(FuDevice) dev = NULL;
	if (!g_file_get_contents (fn, (gchar **) &buf, &bufsz, error))
		return FALSE;
	if (bufsz == 0) {
		g_set_error (error,
			     FWUPD_ERROR,
			     FWUPD_ERROR_INVALID_FILE,
			     "failed to read data from %s", fn);
		return FALSE;
	}
	dev = fu_tpm_eventlog_device_new (buf, bufsz, error);
	if (dev == NULL)
		return FALSE;
	if (!fu_device_setup (dev, error))
		return FALSE;
	fu_plugin_device_add (plugin, dev);
	return TRUE;
}
