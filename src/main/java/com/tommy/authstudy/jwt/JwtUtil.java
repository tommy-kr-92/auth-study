package com.tommy.authstudy.jwt;

import com.tommy.authstudy.entity.UserRoleEnum;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.security.Key;
import java.util.Base64;
import java.util.Date;

@Slf4j(topic = "JwtUtil")
@Component
public class JwtUtil {

	public static final String AUTHORIZATION_HEADER = "Authorization";	// Header KEY 값
	public static final String AUTHORIZATION_KEY = "auth";				// 사용자 권한 값의 KEY
	public static final String BEARER_PREFIX = "Bearer ";				// Token 식별자
	private final long TOKEN_TIME = 60 * 60 * 1000L;					// 토큰 만료 시간

	@Value("${jwt.secret.key}")    // Base64 Encode 한 SecretKey
	private String secretKey;
	private Key key;
	private final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;


	@PostConstruct	// 객체의 생성자가 실행된 후 자동으로 실행
	public void init(){
		// 문자열 형태의 secretKey를 바이트 배열로 변환
		byte[] bytes = Base64.getDecoder().decode(secretKey);

		// HAMC_SHA 알고리즘에 사용될 암호화 키 생성 - 서명을 생성하고 검증 할 때 사용
		key = Keys.hmacShaKeyFor(bytes);
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
	public String getJwtFromHeader(HttpServletRequest request){
		String bearerToken = request.getHeader(AUTHORIZATION_HEADER);
		// StringUtils.hasText() -> 문자열 유효성을 검사하는 메서드
		if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(BEARER_PREFIX)) {
			return bearerToken.substring(7);
		}
		return null;
	}

	// 토큰 검증
	public boolean validateToken(String token) {
		try {
			Jwts.parserBuilder()
					.setSigningKey(key)			// 토큰 생성할 때 사용한 동일한 키(secret key)
					.build()
					.parseClaimsJws(token);
			return true;
		} catch (SecurityException | MalformedJwtException | SignatureException e) {
			log.error("Invalid JWT signature, 유효하지 않는 JWT 서명 입니다.");
		} catch (ExpiredJwtException e){
			log.error("Expired Jwt token, 만료된 JWT token 입니다.");
		} catch (UnsupportedJwtException e){
			log.error("Unsupported JWT token, 지원되지 않는 JWT 토큰 입니다.");
		} catch (IllegalArgumentException e) {
			log.error("JWT claims is empty, 잘못된 JWT 토큰 입니다.");
		}
		return false;
	}

	// 토큰에서 사용자 정보 가져오기
	public Claims getUserInfoFromToken(String token) {
		return Jwts.parserBuilder()		// JWT 파서 빌더 생성
				.setSigningKey(key)		// 토큰 검증을 위한 키 설정
				.build()				// 파서 빌드
				.parseClaimsJws(token)	// 토큰 파싱
				.getBody();				// Claim(페이로드) 추출
	}
}
