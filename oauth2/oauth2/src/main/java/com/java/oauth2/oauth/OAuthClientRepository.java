package com.java.oauth2.oauth;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface OAuthClientRepository extends JpaRepository<OAuthClient, Integer> {

    Optional<OAuthClient> findByEmail(String email);

    OAuthClient findByOauthId(String oauthId);

}
