package com.microservice.devices

import org.slf4j.LoggerFactory
import org.springframework.boot.CommandLineRunner
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.context.annotation.Bean

@SpringBootApplication
class DevicesApplication {
	@Bean
	fun test(): CommandLineRunner {
		return CommandLineRunner {
			val logger = LoggerFactory.getLogger(this.javaClass)
			logger.info("Hello World")
		}
	}
}

fun main(args: Array<String>) {
	runApplication<DevicesApplication>(*args)
}