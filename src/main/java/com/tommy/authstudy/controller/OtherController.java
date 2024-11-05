package com.tommy.authstudy.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/other")
public class OtherController {
	@PostMapping("/request")
	public ResponseEntity<?> request(){
		return ResponseEntity.ok("end-point 도달");
	}
}
