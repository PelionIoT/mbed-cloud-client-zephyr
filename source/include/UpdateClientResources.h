// ----------------------------------------------------------------------------
// Copyright 2016-2017 ARM Ltd.
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

#ifndef MBED_CLOUD_CLIENT_UPDATE_RESOURCES_H
#define MBED_CLOUD_CLIENT_UPDATE_RESOURCES_H

/** \internal \file UpdateClientResources.h */

#ifdef MBED_CLOUD_CLIENT_USER_CONFIG_FILE
#include MBED_CLOUD_CLIENT_USER_CONFIG_FILE
#endif

#include "update-client-hub/update_client_hub.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef MBED_CLOUD_DEV_UPDATE_ID
extern const uint8_t arm_uc_vendor_id[];
extern const uint16_t arm_uc_vendor_id_size;
extern const uint8_t arm_uc_class_id[];
extern const uint16_t arm_uc_class_id_size;
#endif

#ifdef MBED_CLOUD_DEV_UPDATE_CERT
extern const uint8_t arm_uc_default_fingerprint[];
extern const uint16_t arm_uc_default_fingerprint_size;
extern const uint8_t arm_uc_default_certificate[];
extern const uint16_t arm_uc_default_certificate_size;
#endif

#ifdef MBED_CLOUD_DEV_UPDATE_PSK
extern const uint8_t arm_uc_default_psk[];
extern uint16_t arm_uc_default_psk_bits;
#endif

#ifdef __cplusplus
}
#endif

#endif // MBED_CLOUD_CLIENT_UPDATE_RESOURCES_H
