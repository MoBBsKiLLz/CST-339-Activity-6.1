package com.gcu;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

import com.ulisesbocchio.jasyptspringboot.annotation.EnableEncryptableProperties;

@EnableEncryptableProperties
@SpringBootApplication
@ComponentScan({ "com.gcu" })
public class Topic61Application {

	public static void main(String[] args) {
		SpringApplication.run(Topic61Application.class, args);
	}

}
