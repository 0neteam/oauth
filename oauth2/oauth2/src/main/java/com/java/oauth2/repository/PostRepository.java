package com.java.oauth2.repository;

import com.java.oauth2.entity.Post;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface PostRepository extends JpaRepository<Post, Integer> {

    // findAll()는 JpaRepository에 기본적으로 제공되는 메소드입니다.
    List<Post> findAll();

    // 추가적인 메소드를 필요에 따라 정의할 수 있습니다.
    List<Post> findByUseYN(String useYN);

}
