package com.microservice.devices.exceptions

import com.microservice.devices.entities.Device
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.ControllerAdvice
import org.springframework.web.bind.annotation.ExceptionHandler

@ControllerAdvice
class ExceptionHandler {

    @ExceptionHandler(DeviceNotFoundException::class)
    fun handleDeviceNotFoundException(e: DeviceNotFoundException): ResponseEntity<Device> {
        return ResponseEntity.notFound().build()
    }
}