package io.datquad.ApiGateway.repository;

import io.datquad.ApiGateway.model.Token;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface TokenRepository extends JpaRepository<Token, Long> {

    Optional<Token> findByEmailAndStatus(String email, String status); // Find by email and token status

    Optional<Token> findByEmail(String email); // Find by email only

    Optional<Token> findByToken(String token); // Find by the token itself

    Optional<Token> findByEmailAndStatusIn(String email, String[] statuses); // Find by email and multiple statuses

    // You may add additional custom queries if needed
}
