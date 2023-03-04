package com.song.demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@EnableWebSecurity
public class SecurityConfig {
    private final String[] CORS_ALLOW_METHOD = {"GET", "POST", "PATCH", "DELETE", "OPTIONS"};

    @Bean
//  SecurityFilterChain 반환 값이 있고 빈으로 등록한다는 점이다. SecurityFilterChain을 반환하고 빈으로 등록함으로써 컴포넌트 기반의 보안 설정이 가능해진다.
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.cors();
//         cors 란 다른 출처의 리소스에 접근할 때 발생하는 보안 문제를 해결하기 위해 만들어진 메커니즘입니다.
//         출처(Origin)란 동일한 프로토콜, 호스트, 포트를 가진 URI를 의미합니다.
//        다른 출처에서의 리소스에 대한 접근을 제한하는 보안 문제를 해결할 수 있습니다.
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // Rest API 는 기본적으로 Session 이 없다. 상태를 유지 하지 않는다.
                .and()
                .authorizeHttpRequests().antMatchers("/login").permitAll()// 모든 사람이 url을 요청할 수 있다.
                .anyRequest()
                .authenticated()// 나머지 요청에 대해서는 권한이 필요함을 명시한다.
                .and()
                .csrf().disable(); //jwt 토큰을 활용한 Rest 요청시에는 disable 한다.
        return http.build();
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        //
        configuration.setAllowedMethods(Arrays.asList(CORS_ALLOW_METHOD)); // 위에 리스트에 넣어둔것
        configuration.addAllowedHeader("*");//모든 HTTP 헤더를 허용
        configuration.addAllowedOrigin("*");//모든 Origin을 허용하도록 설정

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);// 모든 경로에서 CORS 구성이 적용

        return source;
    }
    @Bean
    public WebSecurityCustomizer customWebSecurityCustomizer() {
        return (web) -> web.ignoring().antMatchers("/csrf" ,  "/" ,"/swagger-resources/**" ,"/swagger-ui.html/**" , "/v2/api-docs/**" , "/webjars/**");
    }
}
