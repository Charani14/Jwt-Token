package io.datquad.ApiGateway.filter;

import io.datquad.ApiGateway.service.JwtService;
import io.datquad.ApiGateway.model.Token;
import io.datquad.ApiGateway.repository.TokenRepository;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class JwtAuthenticationFilter extends AbstractGatewayFilterFactory<JwtAuthenticationFilter.Config> {

    private final JwtService jwtService;
    private final TokenRepository tokenRepository;

    public JwtAuthenticationFilter(JwtService jwtService, TokenRepository tokenRepository) {
        super(Config.class);
        this.jwtService = jwtService;
        this.tokenRepository = tokenRepository;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();

            // Skip public endpoints (e.g., login, register)
            if (isPublicEndpoint(request.getPath().toString())) {
                return chain.filter(exchange);
            }

            // Check if the authorization header is present
            if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                return onError(exchange, "No authorization header", HttpStatus.UNAUTHORIZED);
            }

            String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return onError(exchange, "Invalid authorization header", HttpStatus.UNAUTHORIZED);
            }

            String token = authHeader.substring(7);
            try {
                // Validate the JWT token
                if (jwtService.validateToken(token)) {
                    String userEmail = jwtService.extractUsername(token);

                    // Check the token status in the database
                    Token storedToken = tokenRepository.findByEmail(userEmail)
                            .orElseThrow(() -> new Exception("Token not found in DB"));

                    // If the token is expired or revoked, return a custom message
                    if (!storedToken.getStatus().equals(Token.STATUS_ACTIVE)) {
                        // Optional: Revoke token in the DB if needed
                        // jwtService.revokeToken(token);

                        return onError(exchange, "Token is expired or revoked, please login again.", HttpStatus.UNAUTHORIZED);
                    }

                    // If the token is valid and active, continue the request
                    ServerHttpRequest modifiedRequest = request.mutate()
                            .header("X-Auth-User", userEmail)
                            .build();
                    return chain.filter(exchange.mutate().request(modifiedRequest).build());
                }
            } catch (Exception e) {
                return onError(exchange, e.getMessage(), HttpStatus.UNAUTHORIZED);
            }

            return onError(exchange, "Invalid token", HttpStatus.UNAUTHORIZED);
        };
    }

    // Method to check if the endpoint is public
    private boolean isPublicEndpoint(String path) {
        return path.matches(".*/users/register.*") ||
                path.matches(".*/users/login.*") ||
                path.matches(".*/users/forgot-password.*") ||
                path.matches(".*/users/send-otp.*") ||
                path.matches(".*/users/verify-otp.*") ||
                path.matches(".*/users/update-password.*");
    }

    // Method to handle errors and respond with a custom message
    private Mono<Void> onError(ServerWebExchange exchange, String message, HttpStatus status) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(status);
        response.getHeaders().add("x-error", message);
        return response.setComplete();
    }

    public static class Config {}
}
