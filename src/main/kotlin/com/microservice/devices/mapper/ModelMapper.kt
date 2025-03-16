package com.microservice.devices.mapper

import com.microservice.devices.dto.ModelDto
import com.microservice.devices.entities.Model

fun Model.toDto(): ModelDto = ModelDto(
    id = this.id,
    name = this.name,
    createdAt = this.createdAt,
    createdBy = this.createdBy,
    updatedAt = this.updatedAt,
    updatedBy = this.updatedBy,
)

fun ModelDto.toEntity(): Model = Model(
    id = this.id,
    name = this.name,
    createdAt = this.createdAt,
    createdBy = this.createdBy,
)