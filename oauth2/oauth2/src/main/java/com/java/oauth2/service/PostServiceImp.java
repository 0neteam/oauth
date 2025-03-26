package com.java.oauth2.service;

import com.java.oauth2.entity.BoardEntity;
import com.java.oauth2.entity.PostEntity;
import com.java.oauth2.repository.BoardRepository;
import com.java.oauth2.repository.PostRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;


@Service
@RequiredArgsConstructor  // final 필드에 대한 생성자를 자동 생성하는 Lombok 어노테이션
public class PostServiceImp implements PostService {

    private final PostRepository postRepository;
    private final BoardRepository boardRepository;

    // 전체 게시물 조회
    public List<PostEntity> getAllPosts() {
        return postRepository.findAll();
    }

    // 조건에 맞는 게시물 조회 (예: 사용 여부로 검색)
    public List<PostEntity> getPostsByUseYN(String useYN) {
        return postRepository.findByUseYN(useYN);
    }


}
