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

#include "fota/fota_base.h"
#include "fota/fota_storage.h"

#include "fota_zephyr_mcuboot.h"

int fota_storage_init(void)
{
    return fota_zephyr_mcuboot_init();
}

int fota_storage_query(size_t image_id, fota_header_info_t* image_info)
{
    int result = FOTA_STATUS_INVALID_ARGUMENT;

    if (image_info) {

        manifest_firmware_info_t manifest = { 0 };
        result = fota_zephyr_mcuboot_get_manifest(image_id, &manifest);

        if (result == FOTA_STATUS_SUCCESS) {

            /* FOTA only needs version and digest. */
            image_info->version = manifest.version;
            memcpy(image_info->digest, manifest.payload_digest, FOTA_CRYPTO_HASH_SIZE);
        }
    }

    return result;
}

int fota_storage_set_manifest(size_t image_id, const manifest_firmware_info_t* manifest)
{
    int result = FOTA_STATUS_INVALID_ARGUMENT;

    if (manifest) {
        result = fota_zephyr_mcuboot_set_manifest(image_id, manifest);
    }

    return result;
}

int fota_storage_write(size_t image_id, size_t offset, const uint8_t* buffer, size_t size)
{
    int result = FOTA_STATUS_INVALID_ARGUMENT;

    if (buffer) {
        result = fota_zephyr_mcuboot_write(image_id, offset, buffer, size);
    }

    return result;
}

int fota_storage_install(size_t image_id)
{
    return fota_zephyr_mcuboot_install(image_id);
}

#endif // __ZEPHYR__
