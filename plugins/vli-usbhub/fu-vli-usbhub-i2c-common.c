/*
 * Copyright (C) 2017-2019 VIA Corporation
 * Copyright (C) 2019 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include "fu-vli-usbhub-i2c-common.h"

const gchar *
fu_vli_usbhub_i2c_chip_to_string (FuVliUsbhubI2cChip chip)
{
	if (chip == FU_VLI_USBHUB_I2C_CHIP_MSP430)
		return "MSP430";
	return NULL;
}
