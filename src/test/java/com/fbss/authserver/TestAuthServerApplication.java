package com.fbss.authserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.test.context.TestConfiguration;

@TestConfiguration(proxyBeanMethods = false)
public class TestAuthServerApplication {

    public static void main(String[] args) {
        SpringApplication.from(AuthServerApplication::main).with(TestAuthServerApplication.class).run(args);
    }

}
