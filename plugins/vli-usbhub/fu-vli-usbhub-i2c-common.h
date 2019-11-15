/*
 * Copyright (C) 2017-2019 VIA Corporation
 * Copyright (C) 2019 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include "fu-plugin.h"

typedef enum {
	FU_VLI_USBHUB_I2C_CHIP_UNKNOWN,
	FU_VLI_USBHUB_I2C_CHIP_MSP430,
} FuVliUsbhubI2cChip;

/* Texas Instruments BSL */
#define FU_VLI_USBHUB_I2C_ADDR_WRITE		0x18
#define FU_VLI_USBHUB_I2C_ADDR_READ		0x19

#define FU_VLI_USBHUB_I2C_CMD_WRITE		0x32
#define FU_VLI_USBHUB_I2C_CMD_READ		0x33
#define FU_VLI_USBHUB_I2C_CMD_UPGRADE		0x34

const gchar	*fu_vli_usbhub_i2c_chip_to_string	(FuVliUsbhubI2cChip	 chip);
