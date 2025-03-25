package com.java.oauth2.entity;

import com.fasterxml.jackson.annotation.JsonFormat;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDate;

@Entity
@Table(name = "fileinfo")
@Getter
@ToString
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class FileInfo {
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Integer no;
	
	@Column(nullable = false, length = 100)
	private String orgin;
	
	@Column(nullable = false, length = 100)
	private String name;
	
	@Column(nullable = false, length = 50)
	private String attachPath;
	
	@Column(nullable = false, length = 10)
	private String ext;
	
	@Column(nullable = false)
	private Character useYN;
	
	@CreationTimestamp
    @Column(nullable = false, updatable = false)
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
	private LocalDate regDate;
	
	@Column(nullable = false)
	private Integer regUserNo;
	
	private LocalDate modDate;
	private Integer modUserNo;
	
	@Column(nullable = false, length = 255)
	private String mediaType;

}
