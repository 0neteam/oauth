package com.java.oauth2.oauth;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class OAuthService {

  private final OAuthClientRepository oAuthClientRepository;
  private final BCryptPasswordEncoder passwordEncoder;

  public boolean save(OAuthClient oAuthClient) {
    oAuthClient.setPwd( passwordEncoder.encode(oAuthClient.getPwd()) ); // 암호화 처리
    System.out.println("OAuthService save ");
    return oAuthClientRepository.save(oAuthClient) == null ? false : true;
  }

}
