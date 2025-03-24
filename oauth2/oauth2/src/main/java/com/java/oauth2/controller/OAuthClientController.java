package com.java.oauth2.controller;

import com.java.oauth2.dto.OauthReqDTO;
import com.java.oauth2.dto.CustomOAuth2User;
import com.java.oauth2.entity.OAuthClient;
import com.java.oauth2.service.OAuthServiceImp;
import com.java.oauth2.service.PostServiceImp;
import com.nimbusds.jose.jwk.JWKSet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@RequestMapping("/")
@Slf4j
@Controller
@RequiredArgsConstructor
public class OAuthClientController {

  private final OAuthServiceImp oAuthService;
  private final PostServiceImp postService;
  private final JwtDecoder jwtDecoder;
  private final JWKSet jwkSet;

  @GetMapping("")
  public String home(@AuthenticationPrincipal CustomOAuth2User oAuth2User, Model model, HttpServletRequest request, HttpServletResponse response, @RequestHeader(value = "Authorization", defaultValue = "") String authorizationHeader) {
    return oAuthService.getLoginInfo(request, model);
  }
  
  @ResponseBody
  @GetMapping("/userinfo")
  public OAuthClient userinfo (HttpServletRequest request) {
	return oAuthService.userInfo(request);
  }

  @GetMapping("/signIn")
  public String signIn() {
    return "signIn";
  }

  @GetMapping("/signUp")
  public String signUp() {
    return "signUp";
  }

  @ResponseBody
  @PostMapping("/signUp")
  public boolean signUp(@RequestBody OauthReqDTO oauthReqDTO) {
    return oAuthService.Signup(oauthReqDTO);
  }

  @ResponseBody
  @PostMapping("/signIn")
  public boolean signIn(Model model, @RequestBody OauthReqDTO oauthReqDTO, HttpServletResponse response, HttpSession session) {
    return oAuthService.signIn(model, oauthReqDTO, response, session);
  }

  @GetMapping("/oauth2/logout")
  public String logout(Model model, HttpServletResponse response) {
    return oAuthService.logout(model,response);
  }
  


}
