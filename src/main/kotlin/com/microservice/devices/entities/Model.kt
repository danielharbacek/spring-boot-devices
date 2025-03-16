package com.microservice.devices.entities

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.GeneratedValue
import jakarta.persistence.GenerationType
import jakarta.persistence.Id
import java.time.LocalDateTime

@Entity
data class Model(
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    val id: Long? = null,

    @Column
    val name: String,

    @Column(nullable = false, updatable = false)
    val createdAt: LocalDateTime,

    @Column(nullable = false, updatable = false)
    val createdBy: String,

    @Column(insertable = false, nullable = true)
    val updatedAt: LocalDateTime? = null,

    @Column(insertable = false, nullable = true)
    val updatedBy: String? = null,
)
