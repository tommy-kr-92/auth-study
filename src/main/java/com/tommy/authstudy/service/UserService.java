package com.tommy.authstudy.service;

import com.tommy.authstudy.dto.SignupRequestDto;
import com.tommy.authstudy.entity.User;
import com.tommy.authstudy.entity.UserRoleEnum;
import com.tommy.authstudy.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService {

	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;

	// Admin Register Code
	private final String ADMIN_TOKEN = "AAABnvxRVklrnYxKZ0aHgTBcXukeZygoC";

	public void signup(SignupRequestDto requestDto) {
		String username = requestDto.getUsername();
		String password = passwordEncoder.encode(requestDto.getPassword());

		Optional<User> checkUsername = userRepository.findByUsername(username);
		if (checkUsername.isPresent()){
			throw new IllegalArgumentException("중복된 사용자가 존재합니다.");
		}

		String email = requestDto.getEmail();
		Optional<User> checkEmail = userRepository.findByEmail(email);
		if (checkEmail.isPresent()){
			throw new IllegalArgumentException("중복된 이메일이 존재합니다.");
		}

		UserRoleEnum role = UserRoleEnum.USER;
		if (requestDto.isAdmin()){
			if (!ADMIN_TOKEN.equals(requestDto.getAdminToken())){
				throw new IllegalArgumentException("관리자 암호가 불일치합니다. 관리자에게 문의해주세요.");
			}
			role = UserRoleEnum.ADMIN;
		}

		User user = new User(username, password, email, role);
		userRepository.save(user);
	}
}
