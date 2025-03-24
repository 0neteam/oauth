package com.java.oauth2.service;

import com.java.oauth2.entity.Post;
import java.util.List;

public interface PostService {

    // 전체 게시물 조회
    public List<Post> getAllPosts();

    // 조건에 맞는 게시물 조회 (예: 사용 여부로 검색)
    public List<Post> getPostsByUseYN(String useYN);
}
