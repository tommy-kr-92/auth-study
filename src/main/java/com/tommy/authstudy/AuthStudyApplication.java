package com.tommy.authstudy;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;

@SpringBootApplication(exclude = {SecurityAutoConfiguration.class})
public class AuthStudyApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthStudyApplication.class, args);
	}

}
