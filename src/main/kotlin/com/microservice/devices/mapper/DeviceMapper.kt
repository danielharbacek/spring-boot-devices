package com.microservice.devices.mapper

import com.microservice.devices.dto.CreateDeviceDto
import com.microservice.devices.dto.DeviceDto
import com.microservice.devices.entities.Device
import java.time.LocalDateTime

fun Device.toDto(): DeviceDto = DeviceDto(
    id = this.id,
    model = this.model?.toDto(),
    name = this.name,
    createdAt = this.createdAt,
    createdBy = this.createdBy,
    updatedAt = this.updatedAt,
    updatedBy = this.updatedBy,
)

fun CreateDeviceDto.toEntity(createdBy: String): Device = Device(
    name = this.name,
    createdAt = LocalDateTime.now(),
    createdBy = createdBy,
)