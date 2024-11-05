package com.tommy.authstudy.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tommy.authstudy.dto.LoginRequestDto;
import com.tommy.authstudy.entity.UserRoleEnum;
import com.tommy.authstudy.security.UserDetailsImpl;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;

@Slf4j(topic = "로그인 및 JWT 생성")
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	private final JwtUtil jwtUtil;

	public JwtAuthenticationFilter(JwtUtil jwtUtil) {
		this.jwtUtil = jwtUtil;
	}

	// 로그인 시도
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response )throws AuthenticationException {
		try{
			LoginRequestDto requestDto = new ObjectMapper().readValue(request.getInputStream(), LoginRequestDto.class);
			return getAuthenticationManager().authenticate(
					new UsernamePasswordAuthenticationToken(
							requestDto.getUsername(),
							requestDto.getPassword(),
							null
					)
			);
		} catch (IOException e) {
			log.error(e.getMessage());
			throw new RuntimeException(e.getMessage());
		}
	}

	// 로그인 성공 시 JWT 토큰 발급
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication){
		String username = ((UserDetailsImpl)authentication.getPrincipal()).getUsername();
		UserRoleEnum role = ((UserDetailsImpl) authentication.getPrincipal()).getUser().getRole();

		String token = jwtUtil.createToken(username, role);
		response.addHeader(JwtUtil.AUTHORIZATION_HEADER, token);
	}

	// 로그인 실패 시 Status -> 401
	@Override
	protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception){
		response.setStatus(401);
	}
}
