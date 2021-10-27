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

#include "fota/fota_curr_fw.h"
#include "fota/fota_storage.h"

/**
 * Reads the header of the current firmware.
 *
 * \param[in] header_info Header info structure.
 * \return FOTA_STATUS_SUCCESS on success.
 */
int fota_curr_fw_read_header(fota_header_info_t *header_info)
{
    return fota_storage_query(FOTA_COMPONENT_MAIN_COMP_NUM, header_info);
}

/**
 * Read the digest from the current firmware.
 *
 * \param[out]  buf     Buffer to read into.
 * \return ::FOTA_STATUS_SUCCESS on success.
 */
int fota_curr_fw_get_digest(uint8_t *buf)
{
    int result = FOTA_STATUS_INVALID_ARGUMENT;

    if (buf) {
        fota_header_info_t header_info = { 0 };

        /* current firmware is the same as MAIN component */
        result = fota_storage_query(FOTA_COMPONENT_MAIN_COMP_NUM, &header_info);

        if (result == FOTA_STATUS_SUCCESS) {
            memcpy(buf, header_info.digest, FOTA_CRYPTO_HASH_SIZE);
        }
    }

    return 0;
}

#endif // __ZEPHYR__
