package com.java.oauth2.entity;

import com.fasterxml.jackson.annotation.JsonFormat;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

@Entity
@Table(name = "post")
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class Post {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int no; // 글번호

    private int menuNo; // 메뉴번호 (다른 테이블과 연관)

    @Column(nullable = false, length = 255)
    private String title; // 글제목

    @Column(nullable = false, columnDefinition = "TEXT")
    private String content; // 글내용

    @Column(nullable = false)
    private String regUserNo; // 작성자 (다른 테이블과 연관)

    @Column(nullable = false)
    @CreationTimestamp
    @JsonFormat(pattern = "yyyy.MM.dd HH:mm")
    private LocalDateTime regDate;

    @Column(nullable = false)
    private int viewCount; // 조회수

    @Column(nullable = true)  // NULL을 허용할 수 있도록 설정
    private Integer modUserNo; // 수정자 (다른 테이블과 연관)

    @CreationTimestamp
    @JsonFormat(pattern = "yyyy.MM.dd HH:mm")
    private LocalDateTime modDate; // 수정일자

    @Column(nullable = false, length = 1)
    private String useYN = "Y"; // 사용여부 (기본값 'Y')


}
