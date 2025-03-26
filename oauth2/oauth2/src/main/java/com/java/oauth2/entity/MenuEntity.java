package com.java.oauth2.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Entity
@Table(name = "menu")
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class MenuEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer no;

    @ManyToOne
    @JoinColumn(name = "boardNo")
    private BoardEntity boardNo;

    @Column(nullable = false)
    private Integer orderNo;

    @Column(nullable = false)
    private Integer depth;

    @Column(nullable = false, length = 30)
    private String name;

    @Column(nullable = false)
    private Integer ref;

    @Column(nullable = false)
    private char useYN;

}
