package com.microservice.devices.dto

import java.time.LocalDateTime

data class ModelDto(
    val id: Long?,
    val name: String,
    val createdAt: LocalDateTime,
    val createdBy: String,
    val updatedAt: LocalDateTime?,
    val updatedBy: String?,
)
