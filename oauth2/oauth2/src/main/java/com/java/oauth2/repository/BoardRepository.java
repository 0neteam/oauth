package com.java.oauth2.repository;

import com.java.oauth2.entity.BoardEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository(value = "boardRepository1")
public interface BoardRepository extends JpaRepository<BoardEntity, Integer> {
    BoardEntity findByNo(int no);

}
