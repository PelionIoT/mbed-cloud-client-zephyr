// ----------------------------------------------------------------------------
// Copyright 2019-2021 Pelion Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ----------------------------------------------------------------------------

#if defined(__ZEPHYR__)

#include "fota/fota_block_device.h"

#define TRACE_GROUP "FOTA"

/**
 * Pelion FOTA block device initialize.
 *
 * FOTA uses block device to store the update candidate image.
 *
 * \return ::FOTA_STATUS_SUCCESS on success.
 */
int fota_bd_init(void)
{
    FOTA_ASSERT(0);

    return 0;
}

/**
 * Pelion FOTA block device deinitialize.
 *
 * \return ::FOTA_STATUS_SUCCESS on success.
 */
int fota_bd_deinit(void)
{
    FOTA_ASSERT(0);

    return 0;
}

/**
 * Pelion FOTA block device size getter.
 *
 * \param[out] size The total block device size.
 * \return ::FOTA_STATUS_SUCCESS on success.
 */
int fota_bd_size(size_t *size)
{
    FOTA_ASSERT(0);

    return 0;
}

/**
 * Pelion FOTA block device read.
 *
 * \param[out] buffer Destination buffer to be filled. The buffer size must be greater or equal to the ::size argument.
 * \param[in]  addr   Read address.
 * \param[in]  size   Size to read in bytes. Must be a multiple of the read block size that ::fota_bd_get_read_size() retrieves.
 * \return ::FOTA_STATUS_SUCCESS on success.
 * \note If a failure occurs, it is not possible to determine how many bytes were read successfully.
 */
int fota_bd_read(void *buffer, size_t addr, size_t size)
{
    FOTA_ASSERT(0);

    return 0;
}

/**
 * Pelion FOTA block device program.
 *
 * Programs a block to a block device.
 * You must erase the blocks using :fota_bd_erase() before programming them.
 *
 * \param[in] buffer Source buffer to be programmed.
 * \param[in] addr   Address of the block to begin writing to.
 * \param[in] size   Size to write in bytes. Must be a multiple of the program block size that ::fota_bd_get_program_size() retrieves.
 * \return ::FOTA_STATUS_SUCCESS on success.
 * \note If a failure occurs, it is not possible to determine how many bytes succeeded.
 */
int fota_bd_program(const void *buffer, size_t addr, size_t size)
{
    FOTA_ASSERT(0);

    return 0;
}

/**
 * Pelion FOTA block device erase.
 *
 * Erases blocks on a block device.
 *
 * \param[in] addr Address of a block to begin erasing.
 * \param[in] size Size to erase in bytes. Must be a multiple of the erase block size that ::fota_bd_get_erase_size() retrieves.
 * \return ::FOTA_STATUS_SUCCESS on success.
 */
int fota_bd_erase(size_t addr, size_t size)
{
    FOTA_ASSERT(0);

    return 0;
}

/**
 * Pelion FOTA block device get the size of a readable block.
 *
 * \param[out] read_size The size of a readable block in bytes.
 * \return ::FOTA_STATUS_SUCCESS on success.
 */
int fota_bd_get_read_size(size_t *read_size)
{
    FOTA_ASSERT(0);

    return 0;
}

/**
 * Pelion FOTA block device get the size of a programmable block.
 *
 * \param[out] prog_size The size of a programmable block in bytes.
 * \return ::FOTA_STATUS_SUCCESS on success.
 */
int fota_bd_get_program_size(size_t *prog_size)
{
    FOTA_ASSERT(0);

    return 0;
}

/**
 * Pelion FOTA block device get the size of an erasable block for a given address.
 *
 * \param[in]  addr Address of erasable block.
 * \param[out] erase_size The size of an erasable block in bytes.
 * \return ::FOTA_STATUS_SUCCESS on success.
 */
int fota_bd_get_erase_size(size_t addr, size_t *erase_size)
{
    FOTA_ASSERT(0);

    return 0;
}

/**
 * Pelion FOTA block device get the value of the storage when erased.
 *
 * \param[out] erase_value Erase value, if non-negative.
 *             A negative value means that this block device does not support erase.
 * \return :FOTA_STATUS_SUCCESS on success
 */
int fota_bd_get_erase_value(int *erase_value)
{
    FOTA_ASSERT(0);

    return 0;
}

/**
 * Pelion FOTA block device translate physical address to logical one.
 * It is required that block device addresses will be continuous and start from 0.
 * In most devices, this is the case and this function should simply return the physical address.
 * Devices like like internal flash, where addresses don't start from 0. require a less trivial translation logic.
 *
 * \param[in] phys_addr Physical address.
 * \return Logical address
 */
size_t fota_bd_physical_addr_to_logical_addr(size_t phys_addr)
{
    FOTA_ASSERT(0);

    return 0;
}

/**
 * Read from the current firmware.
 *
 * \param[out] buf       Buffer to read into.
 * \param[in]  offset    Offset in the firmware.
 * \param[in]  size      Size to read in bytes.
 * \param[out] num_read  Number of read bytes.
 * \return ::FOTA_STATUS_SUCCESS on success.
 */
int fota_curr_fw_read(uint8_t *buf, size_t offset, size_t size, size_t *num_read)
{
    FOTA_ASSERT(0);

    return 0;
}

#endif // __ZEPHYR__
