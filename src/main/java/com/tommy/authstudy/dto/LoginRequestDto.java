package com.tommy.authstudy.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class LoginRequestDto {
	private String username;
	private String password;
}
