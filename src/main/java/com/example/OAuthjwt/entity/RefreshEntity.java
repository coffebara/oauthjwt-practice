package com.example.OAuthjwt.entity;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PACKAGE)
public class RefreshEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String username;
    private String refresh;
    private String expired;

    @Builder
    public RefreshEntity(String username, String refresh, String expired) {
        this.username = username;
        this.refresh = refresh;
        this.expired = expired;
    }
}
