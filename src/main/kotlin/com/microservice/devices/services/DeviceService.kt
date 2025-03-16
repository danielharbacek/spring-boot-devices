package com.microservice.devices.services

import com.microservice.devices.dto.CreateDeviceDto
import com.microservice.devices.dto.DeviceDto
import com.microservice.devices.exceptions.DeviceNotFoundException
import com.microservice.devices.mapper.toDto
import com.microservice.devices.mapper.toEntity
import com.microservice.devices.repositories.DeviceRepository
import org.springframework.stereotype.Service

@Service
class DeviceService(
    private val repository: DeviceRepository
) {
    fun getDevices(): List<DeviceDto> {
        return repository.findAllWithModel().map {
            it.toDto()
        }
//        return repository.findDevicesByModelName("model1").map { it.toDto() }
    }

    fun getDevice(id: Long): DeviceDto {
        return repository.findById(id).orElseThrow {
            DeviceNotFoundException()
        }.toDto()
    }

    fun createDevice(device: CreateDeviceDto, user: String): DeviceDto {
        return repository.save(device.toEntity(user)).toDto()
    }
}