package com.microservice.devices.dto

import java.time.LocalDateTime

data class DeviceDto(
    val id: Long?,
    val model: ModelDto?,
    val name: String,
    val createdAt: LocalDateTime?,
    val createdBy: String?,
    val updatedAt: LocalDateTime?,
    val updatedBy: String?,
)
