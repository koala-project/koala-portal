package com.koala.protal;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportResource;

/**
 * @Author Liuyf
 * @Date 2016-08-05
 * @Time 18:20
 * @Description
 */
@EnableAutoConfiguration
@Configuration
@ComponentScan
@ImportResource(locations = "dubbo-custom.xml")
public class Application {

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }

}
