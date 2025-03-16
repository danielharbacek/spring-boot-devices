package com.microservice.devices.repositories

import com.microservice.devices.entities.Device
import org.springframework.data.jpa.repository.EntityGraph
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Query
import org.springframework.stereotype.Repository

@Repository
interface DeviceRepository: JpaRepository<Device, Long> {
    @EntityGraph("Device.model")
    @Query("SELECT d FROM Device d")
    fun findAllWithFullDetails(): List<Device>
}