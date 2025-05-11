package com.microservice.devices

import org.springframework.boot.actuate.info.Info
import org.springframework.boot.actuate.info.InfoContributor
import org.springframework.stereotype.Component

@Component
class InfoProps: InfoContributor {
    override fun contribute(builder: Info.Builder?) {
        builder?.withDetail("name", this::class.simpleName)
    }
}