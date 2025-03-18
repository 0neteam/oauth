package com.java.oauth2.oauth;

import com.fasterxml.jackson.annotation.JsonFormat;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDate;
import java.time.LocalDateTime;

@Entity
@Table(name = "oauthclient")
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class OAuthClient {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private int id;

  @Column(length = 50)
  private String email;
  @Column(length = 50, nullable = false)
  private String username;

  private String pwd;
  private String profilePictureUrl;

  @Column(name = "use_yn", nullable = false, columnDefinition = "boolean default true")
  private boolean useYN;

  @Column(nullable = false)
  @CreationTimestamp
  @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
  private LocalDateTime regDate;

  @Column(nullable = false, columnDefinition = "VARCHAR(255) DEFAULT 'LOCAL'")
  private String issuer;
  @Column(nullable = false)
  private String oauthId;

}
