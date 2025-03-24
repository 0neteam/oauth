package com.java.oauth2.service;

import com.java.oauth2.common.UserUtils;
import com.java.oauth2.dto.CustomOAuth2User;
import com.java.oauth2.dto.OauthReqDTO;
import com.java.oauth2.entity.OAuthClient;
import com.java.oauth2.repository.OAuthClientRepository;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Service;
import org.springframework.ui.Model;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.client.RestClient;

import java.util.List;
import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class OAuthServiceImp implements OAuth2UserService {

  private final OAuthClientRepository oAuthClientRepository;
  private final BCryptPasswordEncoder passwordEncoder;

  private final JwtDecoder jwtDecoder;
  private final JWKSet jwkSet;
  private final PostServiceImp postService;

  public String getLoginInfo(HttpServletRequest request, Model model) {

    HttpSession session = request.getSession();
    CustomOAuth2User social_userinfo = null;
    social_userinfo = UserUtils.getCustomOAuth2User(request);
    log.info("social_userinfo : {}", social_userinfo);

    // 소셜로그인 값이 있는경우
    if (social_userinfo != null) {

      model.addAttribute("issuer", social_userinfo.getIssuer());
      model.addAttribute("name", social_userinfo.getName());
      model.addAttribute("email", social_userinfo.getEmail());

      log.info("social model : {}", model);
      //return "main";
    }

    //쿠키 값 확인
    Cookie[] cookies = request.getCookies();

      if (cookies != null) {
        for (Cookie cookie : cookies) {
          if ("access_token".equals(cookie.getName())) {

            List<JWK> jwks = jwkSet.getKeys();

            String token = cookie.getValue();

            System.out.println("token = " + token);

            try {

              // JwtDecoder를 사용하여 토큰 디코딩
              Jwt jwt = jwtDecoder.decode(token);

              // 🔹 디버깅 로그 출력 (토큰 클레임 및 만료 시간)
              System.out.println("Decoded JWT claims: " + jwt.getClaims());

              // "sub" 클레임 추출
              String email = (String) jwt.getClaims().get("sub");
              String name = (String) jwt.getClaims().get("username");

              System.out.println("controller name : " + name);

              model.addAttribute("email", email);
              model.addAttribute("name", name);

              System.out.println("local login model =" + model);

            } catch (JwtException e) {
              // 토큰 처리 중 오류가 발생한 경우 로그아웃처리
              return "redirect:/oauth2/logout";
            }

          }
        }
      }


      model.addAttribute("cafeList", postService.getPostsByUseYN("Y"));
      model.addAttribute("blogList", postService.getPostsByUseYN("Y"));

    return "main";
  }

  public OAuthClient userInfo (HttpServletRequest request) {

    //쿠키 값 확인
    Cookie[] cookies = request.getCookies();
    OAuthClient oAuthClient = null;

    if (cookies != null) {
      for (Cookie cookie : cookies) {
        if ("access_token".equals(cookie.getName())) {

          List<JWK> jwks = jwkSet.getKeys();

          String token = cookie.getValue();

          System.out.println("userinfo token = " + token);

          try{

            // JwtDecoder를 사용하여 토큰 디코딩
            Jwt jwt = jwtDecoder.decode(token);

            // 🔹 디버깅 로그 출력 (토큰 클레임 및 만료 시간)
            System.out.println("Decoded JWT claims: " + jwt.getClaims());

            // "sub" 클레임 추출
            String userNo = (String) jwt.getClaims().get("userNo");
            String email = (String) jwt.getClaims().get("sub");
            String name = (String) jwt.getClaims().get("username");

            oAuthClient = OAuthClient.builder()
                    .no(Integer.parseInt(userNo))
                    .email(email)
                    .name(name)
                    .build();

          } catch (JwtException e) {
            // 토큰 처리 중 오류가 발생한 경우 로그아웃처리

          }

        }
      }

    }

    return oAuthClient;
  }

  public boolean Signup (@RequestBody OauthReqDTO oauthReqDTO) {

    boolean status = false;

      try {

        System.out.println("oauthReqDTO = " + oauthReqDTO);

        OAuthClient oAuthClient = OAuthClient.builder()
                .name(oauthReqDTO.getName())
                .email(oauthReqDTO.getEmail())
                .issuer("LOCAL")
                .pwd(oauthReqDTO.getPwd())
                //.profilePictureUrl("http://localhost:9000")
                .useYN('Y')
                .build();

        oAuthClient.setPwd(passwordEncoder.encode(oAuthClient.getPwd())); // 암호화 처리
        System.out.println("OAuthService save ");
        System.out.println("oAuthClient = " + oAuthClient);

        OAuthClient savedClient = oAuthClientRepository.save(oAuthClient);
        if (savedClient == null) {
          System.out.println("저장 실패");
          return false;
        }
        System.out.println("저장 성공: " + savedClient);
        return true;
      } catch (Exception e) {
        System.out.println("예외 발생: " + e.getMessage());
        e.printStackTrace();
        return false;
      }

  }

  public boolean signIn (Model model, @RequestBody OauthReqDTO oauthReqDTO, HttpServletResponse response, HttpSession session) {
    boolean status = true;
    try {
      System.out.println("oauthReqDTO = " + oauthReqDTO);
      Map<String, String> resultMap = getToken(oauthReqDTO);
      String access_token = resultMap.get("access_token");

      System.out.println("access_token = " + access_token);

      Cookie cookie = new Cookie("access_token", access_token);

      cookie.setHttpOnly(true); // JavaScript에서 접근 불가
      //cookie.setSecure(true); // HTTPS에서만 전송
      cookie.setPath("/"); //
      cookie.setMaxAge(session.getMaxInactiveInterval());
      response.addCookie(cookie);

      model.addAttribute("cafeList", postService.getPostsByUseYN("Y"));
      model.addAttribute("blogList", postService.getPostsByUseYN("Y"));

    } catch (Exception e) {
      status = false;
      log.info("status : {}", status);
      log.info("Exception occurred: {}", e);

    }

    return status;
  }

  public Map<String, String> getToken(OauthReqDTO oauthReqDTO) {
    MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
    formData.add("grant_type","client_credentials");
    formData.add("client_id", oauthReqDTO.getEmail());
    formData.add("client_secret", oauthReqDTO.getPwd());
    //formData.add("scope", "openid profile");  // ✅ 스코프 추가
    System.out.println("getToken start ");

    return RestClient.create().post()
            .uri("http://l.0neteam.co.kr:9000/oauth2/token")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(formData)
            .retrieve()
            .toEntity(Map.class)
            .getBody();
  }

  public String logout(Model model, HttpServletResponse response) {

    System.out.println("logout test");
    // cookie 초기화
    ResponseCookie targetCookie = ResponseCookie.from("access_token", "")
            .httpOnly(true)
            //.secure(true)
            .path("/")
            .maxAge(0)
            .build();
    response.addHeader(HttpHeaders.SET_COOKIE, targetCookie.toString());

    model.addAttribute("cafeList", postService.getPostsByUseYN("Y"));
    model.addAttribute("blogList", postService.getPostsByUseYN("Y"));

    return "main";
  }

}
