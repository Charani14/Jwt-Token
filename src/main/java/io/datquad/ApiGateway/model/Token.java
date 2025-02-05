package io.datquad.ApiGateway.model;

import jakarta.persistence.*;
import lombok.*;

import java.util.Date;

@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "tokens")
public class Token {

    public static final String STATUS_ACTIVE = "ACTIVE";
    public static final String STATUS_EXPIRED = "EXPIRED";
    public static final String STATUS_REVOKED = "REVOKED";

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String email;

    @Column(nullable = false)
    private Date timestamp;

    @Column(nullable = false)
    private String status; // Using constant values instead of enum

    @Column(nullable = false, unique = true)
    private String token; // Field to store the JWT token string

    public Token(String email, Date timestamp, String status, String token) {
        this.email = email;
        this.timestamp = timestamp;
        this.status = status;
        this.token = token;
    }

    public boolean isExpired() {
        return STATUS_EXPIRED.equalsIgnoreCase(status);
    }

    public boolean isRevoked() {
        return STATUS_REVOKED.equalsIgnoreCase(status);
    }
}
