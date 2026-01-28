// package com.cabbookingsystem.util;

// import jakarta.servlet.FilterChain;
// import jakarta.servlet.ServletException;
// import jakarta.servlet.http.HttpServletRequest;
// import jakarta.servlet.http.HttpServletResponse;
// import lombok.RequiredArgsConstructor;
// import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
// import org.springframework.security.core.context.SecurityContextHolder;
// import org.springframework.security.core.userdetails.UserDetails;
// import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
// import org.springframework.stereotype.Component;
// import org.springframework.util.StringUtils;
// import org.springframework.web.filter.OncePerRequestFilter;

// import java.io.IOException;

// @Component
// @RequiredArgsConstructor
// public class JwtAuthenticationFilter extends OncePerRequestFilter {

//     private final JwtUtil jwtUtil;
//     private final CustomUserDetailsService customUserDetailsService;

//     @Override
//     protected void doFilterInternal(@org.springframework.lang.NonNull HttpServletRequest request, 
//                                     @org.springframework.lang.NonNull HttpServletResponse response,
//                                     @org.springframework.lang.NonNull FilterChain filterChain) throws ServletException, IOException {

//         // Skip JWT processing for public endpoints
//         String requestPath = request.getRequestURI();
        
//         if (isPublicEndpoint(requestPath)) {
//             filterChain.doFilter(request, response);
//             return;
//         }

//         String jwt = getJwtFromRequest(request);

//         if (StringUtils.hasText(jwt)) {
//             boolean isValid = jwtUtil.validateToken(jwt);
            
//             if (isValid) {
//                 String username = jwtUtil.getUsernameFromToken(jwt);

//                 try {
//                     UserDetails userDetails = customUserDetailsService.loadUserByUsername(username);

//                     UsernamePasswordAuthenticationToken authentication = 
//                         new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

//                     authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

//                     SecurityContextHolder.getContext().setAuthentication(authentication);
//                 } catch (Exception e) {
//                     // Log authentication error but continue with request
//                     System.err.println("Error loading user details: " + e.getMessage());
//                 }
//             }
//         }

//         filterChain.doFilter(request, response);
//     }

//     private boolean isPublicEndpoint(String requestPath) {
//         return requestPath.equals("/api/users/register") ||
//                requestPath.equals("/api/users/login") ||
//                requestPath.equals("/api/drivers/register") ||
//                requestPath.equals("/api/drivers/login") ||
//                requestPath.equals("/api/drivers/available") ||
//                requestPath.startsWith("/v3/api-docs/") ||
//                requestPath.startsWith("/swagger-ui/") ||
//                requestPath.equals("/swagger-ui.html");
//     }

//     private String getJwtFromRequest(HttpServletRequest request) {
//         String bearer = request.getHeader("Authorization");
//         if (StringUtils.hasText(bearer) && bearer.startsWith("Bearer ")) {
//             return bearer.substring(7);
//         }
//         return null;
//     }
// }
package com.cabbookingsystem.util;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final CustomUserDetailsService customUserDetailsService;

    /* =====================================================
       THIS IS THE REAL FIX
       ===================================================== */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {

        // ✅ Skip ALL CORS preflight requests
        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            return true;
        }

        String path = request.getRequestURI();

        // ✅ Skip public endpoints
        return path.equals("/api/users/register")
                || path.equals("/api/users/login")
                || path.equals("/api/drivers/register")
                || path.equals("/api/drivers/login")
                || path.equals("/api/drivers/available")
                || path.startsWith("/v3/api-docs")
                || path.startsWith("/swagger-ui")
                || path.equals("/swagger-ui.html");
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        String jwt = getJwtFromRequest(request);

        if (StringUtils.hasText(jwt)) {
            try {
                if (jwtUtil.validateToken(jwt)) {

                    String username = jwtUtil.getUsernameFromToken(jwt);
                    UserDetails userDetails =
                            customUserDetailsService.loadUserByUsername(username);

                    UsernamePasswordAuthenticationToken authentication =
                            new UsernamePasswordAuthenticationToken(
                                    userDetails,
                                    null,
                                    userDetails.getAuthorities()
                            );

                    authentication.setDetails(
                            new WebAuthenticationDetailsSource().buildDetails(request)
                    );

                    SecurityContextHolder.getContext()
                            .setAuthentication(authentication);
                }
            } catch (Exception e) {
                SecurityContextHolder.clearContext();
            }
        }

        filterChain.doFilter(request, response);
    }

    private String getJwtFromRequest(HttpServletRequest request) {
        String bearer = request.getHeader("Authorization");
        if (StringUtils.hasText(bearer) && bearer.startsWith("Bearer ")) {
            return bearer.substring(7);
        }
        return null;
    }
}
