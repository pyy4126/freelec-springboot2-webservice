package com.jojoldu.book.springboot.config.auth;


import com.jojoldu.book.springboot.domain.user.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@RequiredArgsConstructor
@EnableWebSecurity // Spring Security 설정들을 활성화 시켜준다.
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CustomOAuth2UserService customOAuth2UserService;

    /*
        csrf().disable().headers().frameOptions().disable()
        -> h2-console 화면을 사용하기 위해 해당 옵션들을 disable 한다.

        authorizeRequests
        -> URL별 권한 관리를 설정하는 옵션의 시작점이다.
        -> authorizeRequests가 선언되어야만 antMatchers 옵션을 사용할 수 있다.

        antMatchers
        -> 권한 관리 대상을 지정하는 옵션
        -> URL, HTTP 메소드별로 관리가 가능하다.

        anyRequest
        -> 설정된 값들 이외 나머지 URL들을 나타낸다.
        -> 여기서는 authenticated()을 추가하여 나머지 URL들은 모두 인증된 사용자들에게만 허용한다.

        userInfoEndPoint
        -> OAuth2 로그인 성공 이후 사용자 정보를 가져올 때의 설정들을 담당한다.

        userService
        -> 소셜 로그인 성공 시 후속 조치를 진행할 UserService 인터페이스의 구현체를 등록한다.
        -> 리소스 서버(즉, 소셜 서비스들)에서 사용자 정보를 가져온 상태에서
        -> 추가로 진행하고자 하는 기능을 명시할 수 있다.
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .headers().frameOptions().disable()
                .and()
                .authorizeRequests()
                .antMatchers("/", "/css/**", "/images/**", "/js/**", "/h2-console/**", "/profile").permitAll()
                .antMatchers("/api/v1/**").hasRole(Role.USER.name())
                .anyRequest().authenticated()
                .and()
                .logout()
                .logoutSuccessUrl("/")
                .and()
                .oauth2Login()
                .userInfoEndpoint()
                .userService(customOAuth2UserService);
    }
}
