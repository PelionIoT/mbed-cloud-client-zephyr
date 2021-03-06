/*
 * Copyright (c) 2015-2020 ARM Limited. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Note: this macro is needed on armcc to get the the limit macros like UINT16_MAX
#ifndef __STDC_LIMIT_MACROS
#define __STDC_LIMIT_MACROS
#endif

// Note: this macro is needed on armcc to get the the PRI*32 macros
// from inttypes.h in a C++ code.
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#include "include/m2mtlvdeserializer.h"
#include "mbed-client/m2mconstants.h"
#include "mbed-trace/mbed_trace.h"
#include "common_functions.h"

#define TRACE_GROUP "mClt"
#define BUFFER_SIZE 10

bool M2MTLVDeserializer::is_object_instance(const uint8_t *tlv)
{
    return is_object_instance(tlv, 0);
}

bool M2MTLVDeserializer::is_resource(const uint8_t *tlv)
{
    return is_resource(tlv, 0);
}

bool M2MTLVDeserializer::is_multiple_resource(const uint8_t *tlv)
{
    return is_multiple_resource(tlv, 0);
}

bool M2MTLVDeserializer::is_resource_instance(const uint8_t *tlv)
{
    return is_resource_instance(tlv, 0);
}

M2MTLVDeserializer::Error M2MTLVDeserializer::deserialise_object_instances(const uint8_t *tlv,
                                                                           uint32_t tlv_size,
                                                                           M2MObject &object,
                                                                           M2MTLVDeserializer::Operation operation)
{
    tr_debug("M2MTLVDeserializer::deserialise_object_instances()");
    M2MTLVDeserializer::Error error = M2MTLVDeserializer::None;
    if (is_object_instance(tlv)) {
        error = deserialize_object_instances(tlv, tlv_size, 0, object, operation, false);
        if (M2MTLVDeserializer::None == error) {
            error = deserialize_object_instances(tlv, tlv_size, 0, object, operation, true);
        }
    } else {
        tr_error("M2MTLVDeserializer::deserialise_object_instances - NotValid");
        error = M2MTLVDeserializer::NotValid;
    }
    return error;
}

M2MTLVDeserializer::Error M2MTLVDeserializer::deserialize_resources(const uint8_t *tlv,
                                                                    uint32_t tlv_size,
                                                                    M2MObjectInstance &object_instance,
                                                                    M2MTLVDeserializer::Operation operation)
{
    M2MTLVDeserializer::Error error = M2MTLVDeserializer::None;
    if (!is_resource(tlv) && !is_multiple_resource(tlv)) {
        error = M2MTLVDeserializer::NotValid;
    } else {
        error = deserialize_resources(tlv, tlv_size, 0, object_instance, operation, false);
        if (M2MTLVDeserializer::None == error || M2MTLVDeserializer::NotFound == error) {
            if (M2MTLVDeserializer::Put == operation) {
                remove_resources(tlv, tlv_size, object_instance, 0);
            }
            error = deserialize_resources(tlv, tlv_size, 0, object_instance, operation, true);
        }
    }
    return error;
}

M2MTLVDeserializer::Error M2MTLVDeserializer::deserialize_resource(const uint8_t *tlv,
                                                                   uint32_t tlv_size,
                                                                   M2MResource &resource,
                                                                   M2MTLVDeserializer::Operation operation)
{
    M2MTLVDeserializer::Error error = M2MTLVDeserializer::None;
    if (!is_resource(tlv)) {
        error = M2MTLVDeserializer::NotValid;
    } else if (operation != M2MTLVDeserializer::Put) {
        error = M2MTLVDeserializer::NotValid;
    } else {
        error = deserialize_resource(tlv, tlv_size, resource, operation, true);
    }

    return error;
}

M2MTLVDeserializer::Error M2MTLVDeserializer::deserialize_resource_instances(const uint8_t *tlv,
                                                                             uint32_t tlv_size,
                                                                             M2MResource &resource,
                                                                             M2MTLVDeserializer::Operation operation)
{
    M2MTLVDeserializer::Error error = M2MTLVDeserializer::None;
    if (!is_multiple_resource(tlv)) {
        error = M2MTLVDeserializer::NotValid;
    } else {
        uint8_t offset = 2;

        ((tlv[0] & 0x20) == 0) ? offset : offset++;

        uint8_t length = tlv[0] & 0x18;
        if (length == 0x08) {
            offset += 1;
        } else if (length == 0x10) {
            offset += 2;
        } else if (length == 0x18) {
            offset += 3;
        }

        tr_debug("M2MTLVDeserializer::deserialize_resource_instances() - offset %d", offset);
        error = deserialize_resource_instances(tlv, tlv_size, offset, resource, operation, false);
        if (M2MTLVDeserializer::None == error) {
            if (M2MTLVDeserializer::Put == operation) {
                remove_resource_instances(tlv, tlv_size, resource, offset);
            }
            error = deserialize_resource_instances(tlv, tlv_size, offset, resource, operation, true);
        }
    }
    return error;
}

M2MTLVDeserializer::Error M2MTLVDeserializer::deserialize_object_instances(const uint8_t *tlv,
                                                                           uint32_t tlv_size,
                                                                           uint32_t offset,
                                                                           M2MObject &object,
                                                                           M2MTLVDeserializer::Operation operation,
                                                                           bool update_value)
{
    M2MTLVDeserializer::Error error = M2MTLVDeserializer::None;
    TypeIdLength til(tlv, offset);
    til.deserialize();
    offset = til._offset;

    const M2MObjectInstanceList &list = object.instances();
    M2MObjectInstanceList::const_iterator it;
    it = list.begin();

    if (TYPE_OBJECT_INSTANCE == til._type) {
        for (; it != list.end(); it++) {
            if ((*it)->instance_id() == til._id) {
                error = deserialize_resources(tlv, tlv_size, offset, (**it), operation, update_value);
            }
        }
        offset += til._length;

        if (offset < tlv_size) {
            error = deserialize_object_instances(tlv, tlv_size, offset, object, operation, update_value);
        }
    }
    return error;
}

M2MTLVDeserializer::Error M2MTLVDeserializer::deserialize_resources(const uint8_t *tlv,
                                                                    uint32_t tlv_size,
                                                                    uint32_t offset,
                                                                    M2MObjectInstance &object_instance,
                                                                    M2MTLVDeserializer::Operation operation,
                                                                    bool update_value)
{
    M2MTLVDeserializer::Error error = M2MTLVDeserializer::None;
    TypeIdLength til(tlv, offset);
    til.deserialize();
    offset = til._offset;

    const M2MResourceList &list = object_instance.resources();
    M2MResourceList::const_iterator it;
    it = list.begin();

    bool found = false;
    bool multi = false;
    if (TYPE_RESOURCE == til._type || TYPE_RESOURCE_INSTANCE == til._type) {
        multi = false;
        for (; it != list.end(); it++) {
            if ((*it)->name_id() == til._id) {
                found = true;
                if (update_value) {
                    if (til._length > 0) {
                        if (!set_resource_instance_value((*it), tlv + offset, til._length)) {
                            error = M2MTLVDeserializer::OutOfMemory;
                            break;
                        }
                    } else {
                        (*it)->clear_value();
                    }
                    break;
                } else if (0 == ((*it)->operation() & M2MBase::PUT_ALLOWED)) {
                    tr_warn("M2MTLVDeserializer::deserialize_resources() - NOT_ALLOWED");
                    error = M2MTLVDeserializer::NotAllowed;
                    break;
                }
            }
        }
    } else if (TYPE_MULTIPLE_RESOURCE == til._type) {
        multi = true;
        for (; it != list.end(); it++) {
            if ((*it)->supports_multiple_instances() &&
                    (*it)->name_id() == til._id) {
                found = true;
                error = deserialize_resource_instances(tlv, tlv_size, offset, (**it), object_instance, operation, update_value);
            }
        }
    } else {
        error = M2MTLVDeserializer::NotValid;
        return error;
    }

    if (!found) {
        if (M2MTLVDeserializer::Post == operation) {
            //Create a new Resource
            String id;
            id.append_int(til._id);
            M2MResource *resource = object_instance.create_dynamic_resource(id, "", M2MResourceInstance::OPAQUE, true, multi);
            if (resource) {
                resource->set_operation(M2MBase::GET_PUT_POST_DELETE_ALLOWED);
                if (TYPE_MULTIPLE_RESOURCE == til._type) {
                    error = deserialize_resource_instances(tlv, tlv_size, offset, (*resource), object_instance, operation, update_value);
                }
            }
        } else if (M2MTLVDeserializer::Put == operation) {
            error = M2MTLVDeserializer::NotFound;
        }
    }

    offset += til._length;

    if (offset < tlv_size) {
        error = deserialize_resources(tlv, tlv_size, offset, object_instance, operation, update_value);
    }

    return error;
}

M2MTLVDeserializer::Error M2MTLVDeserializer::deserialize_resource(const uint8_t *tlv,
                                                                   uint32_t tlv_size,
                                                                   M2MResource &resource,
                                                                   M2MTLVDeserializer::Operation operation,
                                                                   bool update_value)
{
    M2MTLVDeserializer::Error error = M2MTLVDeserializer::None;
    if (resource.operation() & M2MBase::PUT_ALLOWED) {
        int offset = 0;
        TypeIdLength til(tlv, offset);
        til.deserialize();
        offset = til._offset;

        if (resource.resource_instance_type() == M2MResourceBase::INTEGER) {
            int64_t value = String::convert_array_to_integer(tlv + offset, til._length);
            if ((strcmp(resource.uri_path(), SERVER_LIFETIME_PATH) == 0) && (value < MINIMUM_REGISTRATION_TIME)) {
                // Check that lifetime can't go below 60s
                return M2MTLVDeserializer::NotAccepted;
            } else {
                if (!resource.set_value(value)) {
                    error = M2MTLVDeserializer::OutOfMemory;
                }
            }
        }

        if (!set_resource_instance_value(&resource, tlv + offset, til._length)) {
            error = M2MTLVDeserializer::OutOfMemory;
        }
    } else {
        error = M2MTLVDeserializer::NotAllowed;
    }

    return error;
}

M2MTLVDeserializer::Error M2MTLVDeserializer::deserialize_resource_instances(const uint8_t *tlv,
                                                                             uint32_t tlv_size,
                                                                             uint32_t offset,
                                                                             M2MResource &resource,
                                                                             M2MObjectInstance &object_instance,
                                                                             M2MTLVDeserializer::Operation operation,
                                                                             bool update_value)
{
    M2MTLVDeserializer::Error error = M2MTLVDeserializer::None;
    TypeIdLength til(tlv, offset);
    til.deserialize();
    offset = til._offset;

    if (TYPE_MULTIPLE_RESOURCE == til._type || TYPE_RESOURCE_INSTANCE == til._type) {
        const M2MResourceInstanceList &list = resource.resource_instances();
        M2MResourceInstanceList::const_iterator it;
        it = list.begin();
        bool found = false;
        for (; it != list.end(); it++) {
            if ((*it)->instance_id() == til._id && TYPE_RESOURCE_INSTANCE == til._type) {
                found = true;
                if (update_value) {
                    if (til._length > 0) {
                        if (!set_resource_instance_value((*it), tlv + offset, til._length)) {
                            error = M2MTLVDeserializer::OutOfMemory;
                            break;
                        }
                    } else {
                        (*it)->clear_value();
                    }
                    break;
                } else if (0 == ((*it)->operation() & M2MBase::PUT_ALLOWED)) {
                    error = M2MTLVDeserializer::NotAllowed;
                    break;
                }
            }
        }

        if (!found) {
            if (M2MTLVDeserializer::Post == operation) {
                // Create a new Resource Instance
                M2MResourceInstance *res_instance = object_instance.create_dynamic_resource_instance(resource.name(), "",
                                                                                                     resource.resource_instance_type(),
                                                                                                     true,
                                                                                                     til._id);
                if (res_instance) {
                    res_instance->set_operation(M2MBase::GET_PUT_POST_DELETE_ALLOWED);
                }
            } else if (M2MTLVDeserializer::Put == operation) {
                error = M2MTLVDeserializer::NotFound;
            }
        }
    } else {
        error = M2MTLVDeserializer::NotValid;
        return error;
    }

    offset += til._length;

    if (offset < tlv_size) {
        error = deserialize_resource_instances(tlv, tlv_size, offset, resource, object_instance, operation, update_value);
    }
    return error;
}

M2MTLVDeserializer::Error M2MTLVDeserializer::deserialize_resource_instances(const uint8_t *tlv,
                                                                             uint32_t tlv_size,
                                                                             uint32_t offset,
                                                                             M2MResource &resource,
                                                                             M2MTLVDeserializer::Operation operation,
                                                                             bool update_value)
{
    if (tlv_size < offset + 1) {
        return M2MTLVDeserializer::NotValid;
    }
    M2MTLVDeserializer::Error error = M2MTLVDeserializer::None;
    TypeIdLength til(tlv, offset);
    til.deserialize();
    offset = til._offset;

    if (TYPE_RESOURCE_INSTANCE == til._type) {
        const M2MResourceInstanceList &list = resource.resource_instances();
        M2MResourceInstanceList::const_iterator it;
        it = list.begin();
        bool found = false;
        for (; it != list.end(); it++) {
            if ((*it)->instance_id() == til._id) {
                found = true;
                if (update_value) {
                    if (til._length > 0) {
                        if (!set_resource_instance_value((*it), tlv + offset, til._length)) {
                            error = M2MTLVDeserializer::OutOfMemory;
                            break;
                        }
                    } else {
                        (*it)->clear_value();
                    }
                    break;
                } else if (0 == ((*it)->operation() & M2MBase::PUT_ALLOWED)) {
                    error = M2MTLVDeserializer::NotAllowed;
                    break;
                }
            }
        }
        if (!found) {
            if (M2MTLVDeserializer::Post == operation) {
                error = M2MTLVDeserializer::NotAllowed;
            } else if (M2MTLVDeserializer::Put == operation) {
                // Create a new Resource Instance
                M2MResourceInstance *res_instance = resource.get_parent_object_instance().create_dynamic_resource_instance(
                                                        resource.name(),
                                                        "",
                                                        resource.resource_instance_type(),
                                                        true,
                                                        til._id);
                if (res_instance) {
                    res_instance->set_operation(M2MBase::GET_PUT_DELETE_ALLOWED);
                }
            }

        }
    } else {
        error = M2MTLVDeserializer::NotValid;
        return error;
    }

    offset += til._length;

    if (offset < tlv_size) {
        error = deserialize_resource_instances(tlv, tlv_size, offset, resource, operation, update_value);
    }
    return error;
}

bool M2MTLVDeserializer::is_object_instance(const uint8_t *tlv, uint32_t offset)
{
    bool ret = false;
    if (tlv) {
        uint8_t value = tlv[offset];
        ret = (TYPE_OBJECT_INSTANCE == (value & TYPE_RESOURCE));
    }
    return ret;
}

uint16_t M2MTLVDeserializer::instance_id(const uint8_t *tlv)
{
    TypeIdLength til(tlv, 0);
    til.deserialize();
    uint16_t id = til._id;
    return id;
}

bool M2MTLVDeserializer::is_resource(const uint8_t *tlv, uint32_t offset)
{
    bool ret = false;
    if (tlv) {
        ret = (TYPE_RESOURCE == (tlv[offset] & TYPE_RESOURCE));
    }
    return ret;
}

bool M2MTLVDeserializer::is_multiple_resource(const uint8_t *tlv, uint32_t offset)
{
    bool ret = false;
    if (tlv) {
        ret = (TYPE_MULTIPLE_RESOURCE == (tlv[offset] & TYPE_RESOURCE));
    }
    return ret;
}

bool M2MTLVDeserializer::is_resource_instance(const uint8_t *tlv, uint32_t offset)
{
    bool ret = false;
    if (tlv) {
        ret = (TYPE_RESOURCE_INSTANCE == (tlv[offset] & TYPE_RESOURCE));
    }
    return ret;
}

bool M2MTLVDeserializer::set_resource_instance_value(M2MResourceBase *res, const uint8_t *tlv, const uint32_t size)
{
    bool success = false;
    switch (res->resource_instance_type()) {
        case M2MResourceBase::INTEGER:
        case M2MResourceBase::BOOLEAN:
        case M2MResourceBase::TIME: {
            int64_t value = String::convert_array_to_integer(tlv, size);
            success = res->set_value(value);
            break;
            // Todo! implement conversion for other types as well
        }
        case M2MResourceBase::STRING:
        case M2MResourceBase::OPAQUE:
        case M2MResourceBase::OBJLINK:
            success = res->set_value(tlv, size);
            break;
        case M2MResourceBase::FLOAT: {
            uint32_t value = common_read_32_bit(tlv);
            float float_value = 0;
            memcpy(&float_value, &value, size);
            success = res->set_value_float(float_value);
            break;
        }
        default:
            break;
    }
    return success;
}

void M2MTLVDeserializer::remove_resources(const uint8_t *tlv,
                                          uint32_t tlv_size,
                                          M2MObjectInstance &object_instance,
                                          uint32_t offset_size)
{
    tr_debug("M2MTLVDeserializer::remove_resources");
    uint32_t offset = offset_size;
    const M2MResourceList &list = object_instance.resources();
    M2MResourceList::const_iterator it;

    it = list.begin();
    for (; it != list.end();) {
        bool found = false;
        while (offset < tlv_size) {
            TypeIdLength til(tlv, offset);
            til.deserialize();
            offset = til._offset;
            offset += til._length;
            if ((*it)->name_id() == til._id) {
                offset = offset_size;
                found = true;
                break;
            }
        }
        offset = offset_size;

        // Remove resource if not part of the TLV message
        if (!found) {
            tr_debug("M2MTLVDeserializer::remove_resources - remove resource %" PRId32, (*it)->name_id());
            object_instance.remove_resource((*it)->name());
        } else {
            ++it;
        }
    }
}

void M2MTLVDeserializer::remove_resource_instances(const uint8_t *tlv,
                                                   uint32_t tlv_size,
                                                   M2MResource &resource,
                                                   uint32_t offset_size)
{
    tr_debug("M2MTLVDeserializer::remove_resource_instances");
    uint32_t offset = offset_size;
    const M2MResourceInstanceList &list = resource.resource_instances();
    M2MResourceInstanceList::const_iterator it;
    it = list.begin();

    for (; it != list.end();) {
        bool found = false;
        while (offset < tlv_size) {
            TypeIdLength til(tlv, offset);
            til.deserialize();
            offset = til._offset;
            offset += til._length;
            if ((*it)->instance_id() == til._id) {
                offset = offset_size;
                found = true;
                break;
            }
        }
        offset = offset_size;

        // Remove resource instance if not part of the TLV message
        if (!found) {
            tr_debug("M2MTLVDeserializer::remove_resource_instances - remove resource instance %d", (*it)->instance_id());
            resource.remove_resource_instance((*it)->instance_id());
        } else {
            ++it;
        }
    }
}

TypeIdLength::TypeIdLength(const uint8_t *tlv, uint32_t offset)
    : _tlv(tlv), _offset(offset), _type(tlv[offset] & 0xC0), _id(0), _length(0)
{
}

void TypeIdLength::deserialize()
{
    uint32_t idLength = _tlv[_offset] & ID16;
    uint32_t lengthType = _tlv[_offset] & LENGTH24;
    if (0 == lengthType) {
        _length = _tlv[_offset] & 0x07;
    }
    _offset++;

    deserialiseID(idLength);
    deserialiseLength(lengthType);
}

void TypeIdLength::deserialiseID(uint32_t idLength)
{
    _id = _tlv[_offset++] & 0xFF;
    if (ID16 == idLength) {
        _id = (_id << 8) + (_tlv[_offset++] & 0xFF);
    }
}

void TypeIdLength::deserialiseLength(uint32_t lengthType)
{
    if (lengthType > 0) {
        _length = _tlv[_offset++] & 0xFF;
    }
    if (lengthType > LENGTH8) {
        _length = (_length << 8) + (_tlv[_offset++] & 0xFF);
    }
    if (lengthType > LENGTH16) {
        _length = (_length << 8) + (_tlv[_offset++] & 0xFF);
    }
}
