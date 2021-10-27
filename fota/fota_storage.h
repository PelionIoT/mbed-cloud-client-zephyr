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

#ifndef FOTA_STORAGE_H
#define FOTA_STORAGE_H

#include "fota/fota_header_info.h"
#include "fota/fota_manifest.h"

#ifndef PSA_FWU_MAX_BLOCK_SIZE
#define PSA_FWU_MAX_BLOCK_SIZE 4
#endif

#ifndef FOTA_MAX_BLOCK_SIZE
#define FOTA_MAX_BLOCK_SIZE PSA_FWU_MAX_BLOCK_SIZE
#endif


/**
 * Storage API for third party bootloader support, e.g., TF-M using PSA Update API:
 *  * https://developer.arm.com/documentation/ihi0093/0000
 *
 * API uses Pelion data structures but should eventually be superseded by PSA API.
 */

/**
 * Initialize storage.
 */
int fota_storage_init(void);

/**
 * Get version and digest for image type.
 *
 * \param[in]  image_id    Type of image being installed.
 * \param[out] image_info  Image header.
 * \return ::FOTA_STATUS_SUCCESS on success.
 */
int fota_storage_query(size_t image_id, fota_header_info_t* image_info);

/**
 * Set manifest associated with image type.
 *
 * \param[in]  image_id  Type of image being installed.
 * \param[in]  manifest  Manifest describing image.
 * \return ::FOTA_STATUS_SUCCESS on success.
 */
int fota_storage_set_manifest(size_t image_id, const manifest_firmware_info_t* manifest);

/**
 * Write fragment type.
 *
 * \param[in]  image_id  Type of image being installed.
 * \param[in]  offset    Offset in the image.
 * \param[in]  bufer     Buffer to write.
 * \param[in]  size      Size to write in bytes.
 * \return ::FOTA_STATUS_SUCCESS on success.
 */
int fota_storage_write(size_t image_id, size_t offset, const uint8_t* buffer, size_t size);

/**
 * Install image after being downloaded.
 *
 * \param[in]  image_id  Type of image being installed.
 * \return ::FOTA_STATUS_SUCCESS on success.
 */
int fota_storage_install(size_t image_id);

#endif // FOTA_STORAGE_H
