/*
 * Copyright (C) 2017-2019 VIA Corporation
 * Copyright (C) 2019 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

//#include <string.h>

#include "fu-firmware-common.h"
#include "fu-ihex-firmware.h"

#include "fu-vli-usbhub-common.h"
#include "fu-vli-usbhub-device.h"
#include "fu-vli-usbhub-i2c-common.h"
#include "fu-vli-usbhub-i2c-device.h"

struct _FuVliUsbhubI2cDevice
{
	FuDevice		 parent_instance;
	FuVliUsbhubI2cChip	 chip;
};

G_DEFINE_TYPE (FuVliUsbhubI2cDevice, fu_vli_usbhub_i2c_device, FU_TYPE_DEVICE)

static void
fu_vli_usbhub_i2c_device_to_string (FuDevice *device, guint idt, GString *str)
{
	FuVliUsbhubI2cDevice *self = FU_VLI_USBHUB_I2C_DEVICE (device);
	fu_common_string_append_kv (str, idt, "ChipId",
				    fu_vli_usbhub_i2c_chip_to_string (self->chip));
}

static gboolean
fu_vli_usbhub_i2c_device_probe (FuDevice *device, GError **error)
{
//	FuVliUsbhubI2cDevice *self = FU_VLI_USBHUB_I2C_DEVICE (device);
	/* success */
	return TRUE;
}

static gboolean
fu_vli_usbhub_i2c_device_detach (FuDevice *device, GError **error)
{
	FuVliUsbhubDevice *parent = FU_VLI_USBHUB_DEVICE (fu_device_get_parent (device));
	const guint8 buf[] = {
		FU_VLI_USBHUB_I2C_ADDR_WRITE,
		FU_VLI_USBHUB_I2C_CMD_UPGRADE,
	};
	if (!fu_vli_usbhub_device_i2c_write_data (parent, 0, 0, buf, sizeof(buf), error))
		return FALSE;

	/* avoid power instability */
	fu_device_set_status (device, FWUPD_STATUS_DEVICE_RESTART);
	g_usleep (5000);

	/* success */
	return TRUE;
}

static FuFirmware *
fu_vli_usbhub_i2c_device_prepare_firmware (FuDevice *device,
					   GBytes *fw,
					   FwupdInstallFlags flags,
					   GError **error)
{
	g_autoptr(FuFirmware) firmware = fu_ihex_firmware_new ();
	fu_device_set_status (device, FWUPD_STATUS_DECOMPRESSING);
	if (!fu_firmware_tokenize (firmware, fw, flags, error))
		return NULL;
	return g_steal_pointer (&firmware);
}

static gboolean
fu_vli_usbhub_i2c_device_write_firmware (FuDevice *device,
					FuFirmware *firmware,
					FwupdInstallFlags flags,
					GError **error)
{
	FuVliUsbhubDevice *parent = FU_VLI_USBHUB_DEVICE (fu_device_get_parent (device));
	GPtrArray *records = fu_ihex_firmware_get_records (FU_IHEX_FIRMWARE (firmware));
	guint16 usbver = fu_usb_device_get_spec (FU_USB_DEVICE (device));

	/* transfer by I2C write, and check status by I2C read */
	fu_device_set_status (device, FWUPD_STATUS_DEVICE_WRITE);
	for (guint j = 0; j < records->len; j++) {
		FuIhexFirmwareRecord *rcd = g_ptr_array_index (records, j);
		const gchar *line = rcd->buf->str;
		gsize bufsz;
		guint8 buf[0x40] = { 0x0 };
		guint8 req_len;
		guint retry;

		/* check there's enough data for the smallest possible record */
		if (rcd->buf->len < 11) {
			g_set_error (error,
				     FWUPD_ERROR,
				     FWUPD_ERROR_INVALID_FILE,
				     "line %u is incomplete, length %u",
				     rcd->ln, (guint) rcd->buf->len);
			return FALSE;
		}

		/* check starting token */
		if (line[0] != ':') {
			g_set_error (error,
				     FWUPD_ERROR,
				     FWUPD_ERROR_INVALID_FILE,
				     "invalid starting token on line %u: %s",
				     rcd->ln, line);
			return FALSE;
		}

		/* length, 16-bit address, type */
		req_len = fu_firmware_strparse_uint8 (line + 1);
#if 0
		if (req_len > 32) {
			g_set_error_literal (error,
					     FWUPD_ERROR,
					     FWUPD_ERROR_NOT_SUPPORTED,
					     "max write is 32 bytes");
			return FALSE;
		}
#endif
		if (9 + (guint) req_len * 2 > (guint) rcd->buf->len) {
			g_set_error (error,
				     FWUPD_ERROR,
				     FWUPD_ERROR_INVALID_FILE,
				     "line %u malformed", rcd->ln);
			return FALSE;
		}

		/* write each record directly to the hardware */
		buf[0] = FU_VLI_USBHUB_I2C_ADDR_WRITE;
		buf[1] = FU_VLI_USBHUB_I2C_CMD_WRITE;
		buf[2] = 0x3a; /* ':' */
		buf[3] = req_len;
		buf[4] = fu_firmware_strparse_uint8 (line + 3);
		buf[5] = fu_firmware_strparse_uint8 (line + 5);
		buf[6] = fu_firmware_strparse_uint8 (line + 7);
		for (guint8 i = 0; i < req_len; i++)
			buf[7 + i] = fu_firmware_strparse_uint8 (line + 9 + (i * 2));
		buf[7 + req_len] = fu_firmware_strparse_uint8 (line + 9+ (req_len * 2));
		bufsz = req_len + 8;

		for (retry = 0; retry < 5; retry++) {
			guint8 status = 0xff;
			g_usleep (5 * 1000);
			if (usbver >= 0x0300 || bufsz <= 32) {
				if (!fu_vli_usbhub_device_i2c_write_data (parent,
									  0, 0,
									  buf,
									  bufsz,
									  error))
					return FALSE;
			} else {
				/* for U2, hub data buffer <= 32 bytes */
				if (!fu_vli_usbhub_device_i2c_write_data (parent,
									  0, 1,
									  buf,
									  32,
									  error))
					return FALSE;
				if (!fu_vli_usbhub_device_i2c_write_data (parent,
									  1, 0,
									  buf + 32,
									  bufsz - 32,
									  error))
					return FALSE;
			}

			/* end of file, no need to check status */
			if (req_len == 0 && buf[6] == 0x01 && buf[7] == 0xFF)
				break;

			/* read data to check status */
			g_usleep (5 * 1000);
			if (!fu_vli_usbhub_device_i2c_read_data (parent,
								 FU_VLI_USBHUB_I2C_CMD_READ,
								 &status,
								 error))
				return FALSE;
			if (status == 0)
				break;
		}

		if (retry >= 5) {
			g_set_error_literal (error,
					     G_IO_ERROR,
					     G_IO_ERROR_NOT_SUPPORTED,
					     "I2C status retry failed");
			return FALSE;
		}
		fu_device_set_progress_full (device, (gsize) j, (gsize) records->len);
	}

	/* success */
	return TRUE;
}

static void
fu_vli_usbhub_i2c_device_init (FuVliUsbhubI2cDevice *self)
{
	self->chip = FU_VLI_USBHUB_I2C_CHIP_MSP430;
	fu_device_add_icon (FU_DEVICE (self), "audio-card");
	fu_device_add_flag (FU_DEVICE (self), FWUPD_DEVICE_FLAG_UPDATABLE);
	fu_device_set_logical_id (FU_DEVICE (self), "I2C");
	fu_device_set_summary (FU_DEVICE (self), "I2C Device");		//FIXME
}

static void
fu_vli_usbhub_i2c_device_class_init (FuVliUsbhubI2cDeviceClass *klass)
{
	FuDeviceClass *klass_device = FU_DEVICE_CLASS (klass);
	klass_device->to_string = fu_vli_usbhub_i2c_device_to_string;
	klass_device->probe = fu_vli_usbhub_i2c_device_probe;
	klass_device->detach = fu_vli_usbhub_i2c_device_detach;
	klass_device->write_firmware = fu_vli_usbhub_i2c_device_write_firmware;
	klass_device->prepare_firmware = fu_vli_usbhub_i2c_device_prepare_firmware;
}

FuDevice *
fu_vli_usbhub_i2c_device_new (void)
{
	FuVliUsbhubI2cDevice *self = g_object_new (FU_TYPE_VLI_USBHUB_I2C_DEVICE, NULL);
	return FU_DEVICE (self);
}
