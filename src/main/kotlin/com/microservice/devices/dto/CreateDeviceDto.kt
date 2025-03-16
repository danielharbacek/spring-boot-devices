package com.microservice.devices.dto

import jakarta.validation.constraints.NotBlank

data class CreateDeviceDto(
    @field:NotBlank(message = "Device name cannot be blank")
    val name: String,
)
