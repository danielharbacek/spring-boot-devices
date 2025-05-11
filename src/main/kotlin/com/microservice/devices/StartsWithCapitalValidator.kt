package com.microservice.devices

import jakarta.validation.ConstraintValidator
import jakarta.validation.ConstraintValidatorContext

open class StartsWithCapitalValidator : ConstraintValidator<StartsWithCapital?, String?> {
    override fun isValid(value: String?, context: ConstraintValidatorContext): Boolean {
        return !value.isNullOrEmpty() && Character.isUpperCase(value[0])
    }
}