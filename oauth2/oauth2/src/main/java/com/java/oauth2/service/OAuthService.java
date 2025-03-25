package com.java.oauth2.service;

import com.java.oauth2.dto.OauthReqDTO;
import com.java.oauth2.entity.OAuthClient;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestBody;

import java.util.Map;

public interface OAuthService {

    public String getLoginInfo(HttpServletRequest request, Model model);

    public OAuthClient userInfo (HttpServletRequest request);

    public boolean Signup (@RequestBody OauthReqDTO oauthReqDTO);

    public boolean signIn (Model model, @RequestBody OauthReqDTO oauthReqDTO, HttpServletResponse response, HttpSession session);

    public Map<String, String> getToken(OauthReqDTO oauthReqDTO);

    public String logout(Model model, HttpServletResponse response);

    public String MyPageEdit(HttpServletRequest request, Model model);
}
