package com.ticketing.api_gateway.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import reactor.core.publisher.Mono;

@Component
public class JwtAuthFilter implements WebFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthFilter.class);

    final JwtUtil jwtUtil;

    public JwtAuthFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    public @NonNull Mono<Void> filter(@NonNull ServerWebExchange exchange, @NonNull WebFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();
        logger.info("Incoming request: {}", path);

        Object routeAttr = exchange.getAttributeOrDefault("org.springframework.cloud.gateway.support.ServerWebExchangeUtils.gatewayRoute", null);
        if (routeAttr instanceof Route route) {
            logger.info("Request routed to: {}, URI: {}", route.getId(), route.getUri());
        }

        if (path.contains("/token")) {
            logger.info("Request to /token endpoint, skipping authentications.");
            return chain.filter(exchange);
        }

        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            logger.warn("Authorization header is missing or does not start with 'Bearer '.");
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        String token = authHeader.substring(7);
        logger.info("Extracted token: {}", token);
        if (!jwtUtil.validateToken(token)) {
            logger.warn("Token validation failed for token: {}", token);
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        logger.info("Token validation successful. Proceeding with the request.");
        return chain.filter(exchange);

    }
}
