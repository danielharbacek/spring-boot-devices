package com.microservice.devices.entities

import jakarta.persistence.*
import java.time.LocalDateTime

@Entity
data class Device(

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    val id: Long? = null,

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "model_id", referencedColumnName = "id")
    val model: Model? = null,

    @Column(nullable = false)
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