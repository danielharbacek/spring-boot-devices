package com.microservice.devices.controllers

import com.microservice.devices.dto.CreateDeviceDto
import com.microservice.devices.dto.DeviceDto
import com.microservice.devices.services.DeviceService
import jakarta.validation.Valid
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*

@RestController
@RequestMapping("/devices")
class DeviceController(
    private val service: DeviceService
)  {

    @PostMapping
    fun create(@Valid @RequestBody device: CreateDeviceDto): ResponseEntity<DeviceDto> {
        return ResponseEntity.ok(service.createDevice(device, "admin"))
    }

    @GetMapping
    fun getDevices(): ResponseEntity<List<DeviceDto>> {
        return ResponseEntity.ok(service.getDevices())
    }

    @GetMapping("/{id}")
    fun getDevice(@PathVariable id: Long): ResponseEntity<DeviceDto> {
        return ResponseEntity.ok(service.getDevice(id))
    }
}