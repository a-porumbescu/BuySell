package com.example.buysell;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;

@SpringBootApplication()
@Configuration
public class BuysellApplication {
	public static void main(String[] args) {
		SpringApplication.run(BuysellApplication.class, args);
	}
}