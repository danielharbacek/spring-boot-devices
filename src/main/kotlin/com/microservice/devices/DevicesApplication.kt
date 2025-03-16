package com.microservice.devices

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class DevicesApplication

fun main(args: Array<String>) {
	runApplication<DevicesApplication>(*args)
}
