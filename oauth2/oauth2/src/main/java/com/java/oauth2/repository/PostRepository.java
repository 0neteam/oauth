package com.java.oauth2.repository;

import com.java.oauth2.entity.PostEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface PostRepository extends JpaRepository<PostEntity, Integer> {

    // findAll()는 JpaRepository에 기본적으로 제공되는 메소드입니다.
    List<PostEntity> findAll();

    // 추가적인 메소드를 필요에 따라 정의할 수 있습니다.
    List<PostEntity> findByUseYN(String useYN);

    List<PostEntity> findByMenuNo_BoardNo_Type(Integer type);

}
