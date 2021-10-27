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

#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#include "fota_zephyr_mcuboot.h"
#include "fota_zephyr_helper.h"
#include "fota_zephyr_flashiap.h"

#include "fota/fota_base.h"

#include <devicetree.h>
#include <storage/flash_map.h>

#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>

#define TRACE_GROUP  "UCPI"

/* Address for MCUBOOT header in the active slot */
#ifndef MBED_CONF_UPDATE_CLIENT_APPLICATION_DETAILS
#define MBED_CONF_UPDATE_CLIENT_APPLICATION_DETAILS 0
#endif

/* Flash page write size */
#ifndef MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE
#define MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE 1
#endif

/* consistency check */
#if (MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE == 0)
#error Update client storage page cannot be zero.
#endif

#if SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE < IMAGE_HEADER_SIZE
#error SN_COAP_MAX_BLOCKWISE_PAYLOAD_SIZE must be larger than \
       or equal to MCUBOOTs header size, IMAGE_HEADER_SIZE.
#endif

#define PAGE_MINUS_ONE (MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE - 1)

/**
 * Calculate buffer size for storing activation header.
 */
#if IMAGE_HEADER_SIZE < MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE
/* use page size as buffer size directly */
#define MCUBOOT_HEADER_BUFFER_SIZE MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE
#else
/* round up buffer size and aling to page size */
#define HEADER_PLUS_PAGE_MINUS_ONE (IMAGE_HEADER_SIZE + PAGE_MINUS_ONE)
#define PAGES_PER_HEADER (HEADER_PLUS_PAGE_MINUS_ONE / MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE)
#define MCUBOOT_HEADER_BUFFER_SIZE (PAGES_PER_HEADER * MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE)
#endif

/* align buffer to 4-byte word boundary */
#define MCUBOOT_HEADER_BUFFER_WORDS ((MCUBOOT_HEADER_BUFFER_SIZE + 3) / 4)

static uint32_t fota_zephyr_mcuboot_header[MCUBOOT_HEADER_BUFFER_WORDS] = { 0 };

/**
 * Calculate buffer size for storing image trailer. The buffer is used to
 * ensure page alignment when writing from the end of the flash.
 */
#define IMAGE_TRAILER_SIZE (8 + 16)

#if IMAGE_TRAILER_SIZE < MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE
#define MCUBOOT_TRAILER_BUFFER_SIZE MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE
#else
#define TRAILER_PLUS_PLAGE_MINUS_ONE (IMAGE_TRAILER_SIZE + PAGE_MINUS_ONE)
#define PAGES_PER_TRAILER (TRAILER_PLUS_PLAGE_MINUS_ONE / MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE)
#define MCUBOOT_TRAILER_BUFFER_SIZE  (PAGES_PER_TRAILER * MBED_CONF_UPDATE_CLIENT_STORAGE_PAGE)
#endif

/* align buffer to 4-byte word boundary */
#define MCUBOOT_TRAILER_BUFFER_WORDS ((MCUBOOT_TRAILER_BUFFER_SIZE + 3) / 4)

/**
 * Trailer magic, settings, and offsets.
 */
#define IMAGE_OK_CONFIRMED 0x01
#define IMAGE_OK_NOT_CONFIRMED 0xFF
#define IMAGE_OK_OFFSET 6
#define BOOT_IMG_MAGIC_0_OFFSET 4
#define BOOT_IMG_MAGIC_1_OFFSET 3
#define BOOT_IMG_MAGIC_2_OFFSET 2
#define BOOT_IMG_MAGIC_3_OFFSET 1

#define BOOT_IMG_MAGIC_0 0xF395C277
#define BOOT_IMG_MAGIC_1 0x7FEFD260
#define BOOT_IMG_MAGIC_2 0x0F505235
#define BOOT_IMG_MAGIC_3 0x8079B62C

/**
 * MCUBOOT will by default only test a new firmware image and unless the user
 * application marks the new image as permanent, MCUBOOT will revert the
 * application back to its original image. During development, the user can
 * set FOTA_ZEPHYR_DEFAULT_PERMANENT=1 and all firmware images will
 * automatically be set as permanent. This prevents accidentally reverting
 * back to a previous image when doing application development.
 */
#if defined(FOTA_ZEPHYR_DEFAULT_PERMANENT) \
        && (FOTA_ZEPHYR_DEFAULT_PERMANENT == 1)
#define DEFAULT_IMAGE_OK IMAGE_OK_CONFIRMED
#else
#define DEFAULT_IMAGE_OK IMAGE_OK_NOT_CONFIRMED
#endif

/**
 * Transfer firmare details across function calls.
 * Details are provided in Prepare and used in Activate
 */
static manifest_firmware_info_t fota_zephyr_manifest = { 0 };

/**
 * @brief Round size up to nearest page
 *
 * @param size The size that need to be rounded up
 * @return Returns the size rounded up to the nearest page
 */
static uint32_t fota_zephyr_flashiap_round_up_to_page_size(uint32_t size)
{
    uint32_t page_size = fota_zephyr_flashiap_candidate_get_page_size();

    if (size != 0) {
        size = ((size - 1) / page_size + 1) * page_size;
    }

    return size;
}

/**
 * @brief Get the physicl slot address and size given slot_id
 *
 * @param slot_id Storage location ID.
 * @param slot_addr the slot address is returned in this pointer
 * @param slot_size the slot size is returned in this pointer
 * @return Returns ERR_NONE on success.
 *         Returns ERR_INVALID_PARAMETER on error.
 */
static int fota_zephyr_flashiap_get_slot_addr_size(uint32_t slot_id,
                                                   uint32_t* slot_addr,
                                                   uint32_t* slot_size)
{
    int result = FOTA_STATUS_INVALID_ARGUMENT;

    if (slot_id < FOTA_NUM_COMPONENTS) {
        *slot_addr = 0;
        *slot_size = FLASH_AREA_SIZE(image_1);
        result = FOTA_STATUS_SUCCESS;
    }

    return result;
}

/**
 * @brief Initialise the flash IAP API
 *
 * @param callback function pointer to the PAAL event handler
 * @return Returns ERR_NONE on success.
 *         Returns ERR_INVALID_PARAMETER on error.
 */
int fota_zephyr_mcuboot_init(void)
{
    int result = FOTA_STATUS_INVALID_ARGUMENT;

    int32_t active = fota_zephyr_flashiap_active_init();
    int32_t candidate = fota_zephyr_flashiap_candidate_init();

    if ((active == ARM_UC_FLASHIAP_SUCCESS) && (candidate == ARM_UC_FLASHIAP_SUCCESS)) {
        result = FOTA_STATUS_SUCCESS;
    }

    return result;
}

/**
 * @brief Prepare the storage layer for a new firmware image.
 * @details The storage location is set up to receive an image with
 *          the details passed in the details struct.
 *
 * @param slot_id Storage location ID.
 * @param details Pointer to a struct with firmware details.
 * @param buffer Temporary buffer for formatting and storing metadata.
 * @return Returns ERR_NONE on accept, and signals the event handler with
 *         either DONE or ERROR when complete.
 *         Returns ERR_INVALID_PARAMETER on reject, and no signal is sent.
 */
int fota_zephyr_mcuboot_set_manifest(uint32_t slot_id,
                                     const manifest_firmware_info_t* details)
{
    FOTA_TRACE_INFO("fota_zephyr_mcuboot_set_manifest slot_id %" PRIu32 " details %p",
                    slot_id, details);

    int result = FOTA_STATUS_INVALID_ARGUMENT;

    /* validate input */
    if (details &&
        (slot_id < FOTA_NUM_COMPONENTS)) {
        FOTA_TRACE_INFO("FW size %" PRIu64, details->payload_size);

        uint32_t slot_addr = ARM_UC_FLASH_INVALID_SIZE;
        uint32_t slot_size = ARM_UC_FLASH_INVALID_SIZE;
        uint32_t trailer_size = MCUBOOT_TRAILER_BUFFER_SIZE;

        /* find slot start address */
        result = fota_zephyr_flashiap_get_slot_addr_size(slot_id, &slot_addr, &slot_size);

        /* calculate space for new firmware */
        if ((result == FOTA_STATUS_SUCCESS) && (details->payload_size <= (slot_size - trailer_size))) {

            /* erase all sectors in slot */
            uint32_t erase_addr = slot_addr;

            while (erase_addr < slot_addr + slot_size) {

                /* account for changing sector sizes */
                uint32_t sector_size = fota_zephyr_flashiap_candidate_get_sector_size(erase_addr);
                FOTA_TRACE_INFO("erase: addr %" PRIX32 " size %" PRIX32,
                              erase_addr, sector_size);

                /* erase single sector */
                if (sector_size != ARM_UC_FLASH_INVALID_SIZE) {
                    int32_t status = fota_zephyr_flashiap_candidate_erase(erase_addr, sector_size);
                    if (status == ARM_UC_FLASHIAP_SUCCESS) {
                        erase_addr += sector_size;
                    } else {
                        FOTA_TRACE_ERROR("Flash erase failed with status %" PRIi32, status);
                        result = FOTA_STATUS_INVALID_ARGUMENT;
                        break;
                    }
                } else {
                    FOTA_TRACE_ERROR("Get sector size for addr %" PRIX32 " failed", erase_addr);
                    result = FOTA_STATUS_INVALID_ARGUMENT;
                    break;
                }
            }

        } else {
            result = FOTA_STATUS_INSUFFICIENT_STORAGE;
            FOTA_TRACE_ERROR("Firmware too large! required %" PRIX64 " available: %" PRIX32,
                            details->payload_size, slot_size - trailer_size);
        }

        if (result == FOTA_STATUS_SUCCESS) {

            /* store firmware deatils in global */
            memcpy(&fota_zephyr_manifest, details, sizeof(manifest_firmware_info_t));
        }
    }

    return result;
}

/**
 * @brief Write a fragment to the indicated storage location.
 * @details The storage location must have been allocated using the Prepare
 *          call. The call is expected to write the entire fragment before
 *          signaling completion.
 *
 * @param slot_id Storage location ID.
 * @param offset Offset in bytes to where the fragment should be written.
 * @param buffer Pointer to buffer struct with fragment.
 * @return Returns ERR_NONE on accept, and signals the event handler with
 *         either DONE or ERROR when complete.
 *         Returns ERR_INVALID_PARAMETER on reject, and no signal is sent.
 */
int fota_zephyr_mcuboot_write(uint32_t slot_id,
                              uint32_t offset,
                              const uint8_t* buffer,
                              size_t size)
{
    /* find slot address and size */
    uint32_t slot_addr = ARM_UC_FLASH_INVALID_SIZE;
    uint32_t slot_size = ARM_UC_FLASH_INVALID_SIZE;
    int result = fota_zephyr_flashiap_get_slot_addr_size(slot_id,
                                                         &slot_addr,
                                                         &slot_size);

    if (buffer && result == FOTA_STATUS_SUCCESS) {
        FOTA_TRACE_INFO("fota_zephyr_mcuboot_Write: %p %" PRIX32 " %" PRIX32 " %" PRIX32,
                      buffer, size, slot_addr, offset);

        /* set default error */
        result = FOTA_STATUS_INVALID_ARGUMENT;

        /**
         * Catch MCUBOOT header at offset 0 and store it in buffer for later activation.
         */
        const uint8_t* write_buffer = buffer;
        uint32_t write_size = size;
        uint32_t write_offset = offset;

        if (write_offset == 0) {
            FOTA_TRACE_INFO("cache MCUBOOT header for later activation");

            /* copy header to buffer */
            memcpy(fota_zephyr_mcuboot_header, write_buffer, MCUBOOT_HEADER_BUFFER_SIZE);

            /* reconfigure parameters to write after header */
            write_buffer += MCUBOOT_HEADER_BUFFER_SIZE;
            write_size -= MCUBOOT_HEADER_BUFFER_SIZE;
            write_offset += MCUBOOT_HEADER_BUFFER_SIZE;
        }

        /* find physical address of the write */
        uint32_t page_size = fota_zephyr_flashiap_candidate_get_page_size();
        uint32_t physical_address = slot_addr + write_offset;

        /* if last chunk, pad out to page_size aligned size */
        if ((write_size % page_size != 0) &&
            ((write_offset + write_size) >= fota_zephyr_manifest.payload_size)) {
            write_size = fota_zephyr_flashiap_round_up_to_page_size(write_size);
        }

        /* check page alignment of the program address and size */
        if ((write_size % page_size == 0) && (physical_address % page_size == 0)) {
            FOTA_TRACE_INFO("programming addr %" PRIX32 " size %" PRIX32,
                            physical_address, write_size);

            /* write pages */
            int status = ARM_UC_FLASHIAP_FAIL;

            if (write_size) {
                status = fota_zephyr_flashiap_candidate_program(write_buffer,
                                                                physical_address,
                                                                write_size);
            } else {
                status = ARM_UC_FLASHIAP_SUCCESS;
            }

            if (status != ARM_UC_FLASHIAP_SUCCESS) {
                FOTA_TRACE_ERROR("fota_zephyr_flashiap_candidate_program failed");
            } else {
                result = FOTA_STATUS_SUCCESS;
            }
        } else {
            FOTA_TRACE_ERROR("program size %" PRIX32 " or address %" PRIX32
                             " not aligned to page size %" PRIX32, write_size,
                             physical_address, page_size);
        }
    } else {
        result = FOTA_STATUS_INVALID_ARGUMENT;
    }

    return result;
}

/**
 * @brief Set the firmware image in the slot to be the new active image.
 * @details This call is responsible for initiating the process for
 *          applying a new/different image. Depending on the platform this
 *          could be:
 *           * An empty call, if the installer can deduce which slot to
 *             choose from based on the firmware details.
 *           * Setting a flag to indicate which slot to use next.
 *           * Decompressing/decrypting/installing the firmware image on
 *             top of another.
 *
 * @param slot_id Storage location ID.
 * @return Returns ERR_NONE on accept, and signals the event handler with
 *         either DONE or ERROR when complete.
 *         Returns ERR_INVALID_PARAMETER on reject, and no signal is sent.
 */
int fota_zephyr_mcuboot_install(uint32_t slot_id)
{
    FOTA_TRACE_INFO("fota_zephyr_mcuboot_install");

    uint32_t slot_addr = ARM_UC_FLASH_INVALID_SIZE;
    uint32_t slot_size = ARM_UC_FLASH_INVALID_SIZE;

    int result = fota_zephyr_flashiap_get_slot_addr_size(slot_id, &slot_addr, &slot_size);

    /**
     * Get active images's MCUBOOT header hash and total size.
     */
    arm_uc_hash_t header_hash_active = { 0 };
    uint32_t total_size = 0;

    if (result == FOTA_STATUS_SUCCESS) {
        result = fota_zephyr_mcuboot_get_hash_from_header(
                        fota_zephyr_flashiap_active_read,
                        MBED_CONF_UPDATE_CLIENT_APPLICATION_DETAILS,
                        &header_hash_active,
                        &total_size);
    }

    /**
     * Get candidate image's MCUBOOT header hash.
     */
    arm_uc_hash_t header_hash_candidate = { 0 };

    /* find TLV address from header cache */
    image_header_t* header_cache = (image_header_t*) fota_zephyr_mcuboot_header;

    if ((result == FOTA_STATUS_SUCCESS) && (header_cache->ih_magic == IMAGE_MAGIC)) {

        FOTA_TRACE_INFO("magic: %" PRIX32, header_cache->ih_magic);
        FOTA_TRACE_INFO("load: %" PRIX32, header_cache->ih_load_addr);
        FOTA_TRACE_INFO("hdr: %" PRIX16, header_cache->ih_hdr_size);
        FOTA_TRACE_INFO("img: %" PRIX32, header_cache->ih_img_size);
        FOTA_TRACE_INFO("prot: %" PRIX16, header_cache->ih_protect_tlv_size);

        uint32_t tlv_address = slot_addr +
                               header_cache->ih_hdr_size +
                               header_cache->ih_img_size;

        /* search TLV for hash */
        result = fota_zephyr_mcuboot_get_hash_from_tlv(fota_zephyr_flashiap_candidate_read,
                                                       tlv_address,
                                                       &header_hash_candidate);

        /**
         * If hash wasn't found, assume we just searched the optional protected TLV.
         * Proceed to the main TLV and search for hash.
         */
        if ((result != FOTA_STATUS_SUCCESS) && header_cache->ih_protect_tlv_size) {

            tlv_address += header_cache->ih_protect_tlv_size;
            result = fota_zephyr_mcuboot_get_hash_from_tlv(fota_zephyr_flashiap_candidate_read,
                                                           tlv_address,
                                                           &header_hash_candidate);
        }

        if (result == FOTA_STATUS_SUCCESS) {
            /**
             * Write details to KCM.
             * The active header hash is used to identify which key-value pair to replace.
             */
            fota_zephyr_mcuboot_set_kcm_details(&header_hash_active,
                                                &header_hash_candidate,
                                                &fota_zephyr_manifest);
        } else {
            FOTA_TRACE_ERROR("No hash found in candidate image");
        }
    }

    /**
     * Write MCUBOOT trailer.
     */
    FOTA_TRACE_INFO("write MCUBOOT trailer");

    /**
     * MCUBOOT will look for a trailer at the end of the candiate storage slot.
     *
     * If the trailer magic is good and the IMAGE_OK flag is unset, MCUBOOT will
     * perform a test update, which will be reverted on the next boot unless the
     * user application marks the image as permanent.
     *
     * If the trailer magic is good and the IMAGE_OK flag is set, MCUBOOT will
     * perform a permanent update, which won't be reverted.
     *
     * https://github.com/mcu-tools/mcuboot/blob/master/docs/design.md
     */
    uint32_t trailer_buffer[MCUBOOT_TRAILER_BUFFER_WORDS] = { 0 };

    trailer_buffer[MCUBOOT_TRAILER_BUFFER_WORDS - IMAGE_OK_OFFSET] = DEFAULT_IMAGE_OK;

    trailer_buffer[MCUBOOT_TRAILER_BUFFER_WORDS - BOOT_IMG_MAGIC_0_OFFSET] = BOOT_IMG_MAGIC_0;
    trailer_buffer[MCUBOOT_TRAILER_BUFFER_WORDS - BOOT_IMG_MAGIC_1_OFFSET] = BOOT_IMG_MAGIC_1;
    trailer_buffer[MCUBOOT_TRAILER_BUFFER_WORDS - BOOT_IMG_MAGIC_2_OFFSET] = BOOT_IMG_MAGIC_2;
    trailer_buffer[MCUBOOT_TRAILER_BUFFER_WORDS - BOOT_IMG_MAGIC_3_OFFSET] = BOOT_IMG_MAGIC_3;

    /* MCUBOOT header buffer is checked for alignment at compile time */
    int status = fota_zephyr_flashiap_candidate_program((uint8_t*) trailer_buffer,
                                                        slot_addr + slot_size - sizeof(trailer_buffer),
                                                        sizeof(trailer_buffer));

    if (status == ARM_UC_FLASHIAP_SUCCESS) {

        /**
         * Final step in activation, write MCUBOOT header.
         */
        FOTA_TRACE_INFO("write activation header");

        /* MCUBOOT header buffer is checked for alignment at compile time */
        status = fota_zephyr_flashiap_candidate_program((uint8_t*) fota_zephyr_mcuboot_header,
                                                        slot_addr,
                                                        sizeof(fota_zephyr_mcuboot_header));

        if (status == ARM_UC_FLASHIAP_SUCCESS) {
            result = FOTA_STATUS_SUCCESS;

        } else {
            FOTA_TRACE_ERROR("unable to write MCUBOOT header");
            result = FOTA_STATUS_STORAGE_WRITE_FAILED;
        }
    } else {
        FOTA_TRACE_ERROR("unable to write MCUBOOT trailer");
        result = FOTA_STATUS_STORAGE_WRITE_FAILED;
    }

    return result;
}

/**
 * @brief Get firmware details for the firmware image in the slot passed.
 * @details This call populates the passed details struct with information
 *          about the firmware image in the slot passed. Only the fields
 *          marked as supported in the capabilities bitmap will have valid
 *          values.
 *
 * @param details Pointer to firmware details struct to be populated.
 * @return Returns ERR_NONE on accept, and signals the event handler with
 *         either DONE or ERROR when complete.
 *         Returns ERR_INVALID_PARAMETER on reject, and no signal is sent.
 */
int fota_zephyr_mcuboot_get_manifest(uint32_t slot_id,
                                           manifest_firmware_info_t* details)
{
    FOTA_TRACE_INFO("fota_zephyr_mcuboot_get_manifest");

    (void) slot_id;

    int result = FOTA_STATUS_INVALID_ARGUMENT;

    if (details) {

        /* parse MCUBOOT header and get hash from TLV struct and total size */
        arm_uc_hash_t header_hash = { 0 };
        uint32_t total_size = 0;

        fota_zephyr_mcuboot_get_hash_from_header(fota_zephyr_flashiap_active_read,
                                                 MBED_CONF_UPDATE_CLIENT_APPLICATION_DETAILS,
                                                 &header_hash,
                                                 &total_size);

        /* use MCUBOOT hash to lookup firmware details in KCM */
        result = fota_zephyr_mcuboot_get_kcm_details(&header_hash, details);

        /* if no details were found in KCM */
        if (result != FOTA_STATUS_SUCCESS) {

            /*  */
            details->version = 0;

#if defined(ARM_UC_FEATURE_DELTA_PAAL) && (ARM_UC_FEATURE_DELTA_PAAL == 1)
            /* calculate hash from active image */
            result = fota_zephyr_mcuboot_calculate_hash(fota_zephyr_flashiap_active_read,
                                                        MBED_CONF_UPDATE_CLIENT_APPLICATION_DETAILS,
                                                        total_size,
                                                        &(details->payload_digest));

            /* on success */
            if (result == FOTA_STATUS_SUCCESS) {

                details->payload_size = total_size;

                /**
                 * Write details to KCM. The first parameter is supposed to be
                 * the active image hash so that the details can be written in
                 * the opposite slot, using the second parameter as key. Since
                 * both slots are empty, passing in the same hash as both
                 * parameters lets the function operate as intended.
                 */
                result = fota_zephyr_mcuboot_set_kcm_details(&header_hash,
                                                             &header_hash,
                                                             details);
            }
#else
            /* use hash from MCUBOOT header */
            memcpy(details->payload_digest, &header_hash, sizeof(arm_uc_hash_t));
            result = FOTA_STATUS_SUCCESS;
#endif
        }

#if FOTA_TRACE_DBG
        printf("[TRACE][SRCE] image hash: ");
        for (size_t index = 0; index < sizeof(arm_uc_hash_t); index++) {
            printf("%02X", details->payload_digest[index]);
        }
        printf("\r\n");
#endif
    }

    return result;
}

#endif /* __ZEPHYR__ */
