package com.custom.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class iAmController {

	@GetMapping("/demo")
	public String demo() {
		
		return "demo";
	}
}
