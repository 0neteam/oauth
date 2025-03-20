package com.java.oauth2.oauth;

import com.java.oauth2.common.UserUtils;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestClient;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@Controller
@RequiredArgsConstructor
public class OAuthClientController {

  private final OAuthService oAuthService;

  private final JwtDecoder jwtDecoder;

  private final JWKSet jwkSet;

  @GetMapping("/")
  public String home(@AuthenticationPrincipal CustomOAuth2User oAuth2User, Model model, HttpServletRequest request, HttpServletResponse response, @RequestHeader(value = "Authorization", defaultValue = "") String authorizationHeader) {

    System.out.println("home start test");

    //소셜 로그인 값 확인
    HttpSession session = request.getSession();
    CustomOAuth2User social_userinfo = null;
    social_userinfo = UserUtils.getCustomOAuth2User(request);
    log.info("social_userinfo : {}", social_userinfo);

    // 소셜로그인 값이 있는경우
    if(social_userinfo != null) {

      model.addAttribute("issuer", social_userinfo.getIssuer());
      model.addAttribute("name", social_userinfo.getName());
      model.addAttribute("id", social_userinfo.getId());
      log.info("model : {}", model);
      return "main";
    }

    //쿠키 값 확인
    Cookie[] cookies = request.getCookies();
    //
    if (cookies != null) {
      for (Cookie cookie : cookies) {
        if ("access_token".equals(cookie.getName())) {

          List<JWK> jwks = jwkSet.getKeys();

          String token = cookie.getValue();

          System.out.println("token = " + token);

          try{

            // JwtDecoder를 사용하여 토큰 디코딩
            Jwt jwt = jwtDecoder.decode(token);

            // 🔹 디버깅 로그 출력 (토큰 클레임 및 만료 시간)
            System.out.println("Decoded JWT claims: " + jwt.getClaims());

            // "sub" 클레임 추출
            String subValue = (String) jwt.getClaims().get("sub");

            model.addAttribute("id", subValue);

          } catch (JwtException e) {
            // 토큰 처리 중 오류가 발생한 경우 로그아웃처리
             return "redirect:/oauth2/logout";
          }


          return "main";
        }
      }
    }
    return "signIn";
  }

  @ResponseBody
  @GetMapping("/callback")
  public String callback() {
    System.out.println("callback test");
    return "Naver";
  }

  @GetMapping("/signIn")
  public String signIn() {
    System.out.println("sign In test");
    return "signIn";
  }

  @GetMapping("/signUp")
  public String signUp() {
    System.out.println("signUp test");
    return "signUp";
  }

  @ResponseBody
  @PostMapping("/signUp")
  public boolean signUp(@RequestBody OauthReqDTO oauthReqDTO, HttpServletResponse response, HttpSession session) {
    boolean status = true;
    try {
      System.out.println("oauthReqDTO = " + oauthReqDTO);

      OAuthClient oAuthClient = OAuthClient.builder()
              .name("홍길동")
              .email(oauthReqDTO.getId())
              .issuer("LOCAL")
              .pwd(oauthReqDTO.getPwd())
              //.profilePictureUrl("http://localhost:9000")
              .oauthId("0")
              .useYN(true)
              .build();

      status = oAuthService.save(oAuthClient);

      System.out.println("status = " + status);

    } catch (Exception e) {
      status = false;
    }
    return status;
  }

  @ResponseBody
  @PostMapping("/signIn")
  public boolean signIn(@RequestBody OauthReqDTO oauthReqDTO, HttpServletResponse response, HttpSession session) {
    boolean status = true;
    try {
      System.out.println("oauthReqDTO = " + oauthReqDTO);
      Map<String, String> resultMap = getToken(oauthReqDTO);
      String access_token = resultMap.get("access_token");

      System.out.println("access_token = " + access_token);

      Cookie cookie = new Cookie("access_token", access_token);
      cookie.setPath("/");
      cookie.setHttpOnly(true); // JavaScript에서 접근 불가
      cookie.setSecure(true); // HTTPS에서만 전송
      cookie.setPath("/");
      cookie.setMaxAge(session.getMaxInactiveInterval());


      response.addCookie(cookie);
    } catch (Exception e) {
      status = false;
    }
    return status;
  }

  private Map<String, String> getToken(OauthReqDTO oauthReqDTO) {
    MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
    formData.add("grant_type","client_credentials");
    formData.add("client_id", oauthReqDTO.getId());
    formData.add("client_secret", oauthReqDTO.getPwd());
    //formData.add("scope", "openid profile");  // ✅ 스코프 추가
    System.out.println("getToken start ");

    return RestClient.create().post()
            .uri("http://leejihyun.co.kr:9000/oauth2/token")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(formData)
            .retrieve()
            .toEntity(Map.class)
            .getBody();
  }


  @GetMapping("/oauth2/logout")
  public String logout(HttpServletResponse response) {
    // cookie 초기화
    ResponseCookie targetCookie = ResponseCookie.from("access_token", "")
            .httpOnly(true).secure(true).path("/").maxAge(0).build();
    response.addHeader(HttpHeaders.SET_COOKIE, targetCookie.toString());
    return "signIn";
  }




}
