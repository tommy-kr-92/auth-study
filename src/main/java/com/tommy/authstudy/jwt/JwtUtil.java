package com.tommy.authstudy.jwt;

import com.tommy.authstudy.entity.UserRoleEnum;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.Value;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Base64;
import java.util.Date;

@Slf4j
@Component
public class JwtUtil {

	public static final String AUTHORIZATION_HEADER = "Authorization";	// Header KEY 값
	public static final String AUTHORIZATION_KEY = "auth";				// 사용자 권한 값의 KEY
	public static final String BEARER_PREFIX = "Bearer ";				// Token 식별자
	private final long TOKEN_TIME = 60 * 60 * 1000L;					// 토큰 만료 시간

	@Value("${jwt.secret.key}")	// Base64 Encode 한 SecretKey
	private String secretKey;
	private Key key;
	private final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;


	@PostConstruct	// 객체의 생성자가 실행된 후 자동으로 실행
	public void init(){
		byte[] bytes = Base64.getDecoder().decode(secretKey);	// 문자열 형태의 secretKey를 바이트 배열로 변환
		key = Keys.hmacShaKeyFor(bytes);	// HAMC_SHA 알고리즘에 사용될 암호화 키 생성 - 서명을 생성하고 검증 할 때 사용
	}

	// 토큰 생성
	public String createToken(String username, UserRoleEnum role) {
		Date date = new Date();
		return BEARER_PREFIX +
				Jwts.builder()
						.setSubject(username)									// 사용자 식별자값(ID)
						.claim(AUTHORIZATION_KEY, role)							// 사용자 권한
						.setExpiration(new Date(date.getTime() + TOKEN_TIME))	// 만료시간
						.setIssuedAt(date)										// 발급일
						.signWith(key, signatureAlgorithm)						// 암호화 알고리즘
						.compact();
	}
	// header 에서 JWT 가져오기
	// 토큰 검증
	// 토큰에서 사용자 정보 가져오기
}
