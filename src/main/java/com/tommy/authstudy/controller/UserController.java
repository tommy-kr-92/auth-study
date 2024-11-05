package com.tommy.authstudy.controller;

import com.tommy.authstudy.dto.SignupRequestDto;
import com.tommy.authstudy.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@Slf4j
@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
public class UserController {

	private final UserService userService;

	@PostMapping("/signup")
	public ResponseEntity<?> signup (@Valid @RequestBody SignupRequestDto requestDto, BindingResult bindingResult){

		List<FieldError> fieldErrors = bindingResult.getFieldErrors();
		if (bindingResult.hasErrors()){
			for (FieldError fieldError : bindingResult.getFieldErrors()){
				log.error("{} field : {}", fieldError.getField(), fieldError.getDefaultMessage());
			}
			return ResponseEntity.badRequest().body("회원가입 입력 필드를 확인해주세요.");
		}

		userService.signup(requestDto);
		return ResponseEntity.ok().build();
	}
}
