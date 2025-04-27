package com.microservice.devices

import org.aspectj.lang.ProceedingJoinPoint
import org.aspectj.lang.annotation.Around
import org.aspectj.lang.annotation.Aspect
import org.springframework.stereotype.Component
import java.util.logging.Logger

annotation class LogAspect

@Aspect
@Component
class TestAspect {

    private val logger = Logger.getLogger(TestAspect::class.java.name)

    @Around("execution(* com.microservice.devices..*(..))")
    fun test(joinPoint: ProceedingJoinPoint): Any? {
        logger.info("Running test aspect")
        val result = joinPoint.proceed()
        logger.info("Called function ${joinPoint.signature.name} of ${joinPoint.target.javaClass.simpleName}")
        logger.info("Parameters: ${joinPoint.args.joinToString(",")}")
        logger.info("Returned value: $result")
        return result
    }

    @Around("@annotation(LogAspect)")
    fun annotationTest(joinPoint: ProceedingJoinPoint): Any? {
        logger.info("Running annotationTest")
        val result = joinPoint.proceed()
        logger.info("Called function ${joinPoint.signature.name} of ${joinPoint.target.javaClass.simpleName}")
        logger.info("Parameters: ${joinPoint.args.joinToString(",")}")
        logger.info("Returned value: $result")
        return result
    }
}