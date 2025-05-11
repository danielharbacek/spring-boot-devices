package com.microservice.devices

import jakarta.validation.Constraint
import jakarta.validation.Payload
import kotlin.reflect.KClass

@MustBeDocumented
@Constraint(validatedBy = [StartsWithCapitalValidator::class])
@Target(AnnotationTarget.VALUE_PARAMETER,AnnotationTarget.FIELD)
@Retention(AnnotationRetention.RUNTIME)
annotation class StartsWithCapital(
    val message: String = "The string must start with a capital letter",
    val groups: Array<KClass<*>> = [],
    val payload: Array<KClass<out Payload>> = []
)