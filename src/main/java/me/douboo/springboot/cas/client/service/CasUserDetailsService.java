package me.douboo.springboot.cas.client.service;

import java.util.ArrayList;
import java.util.Collection;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.cas.authentication.CasAssertionAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * 用于加载用户信息
 * 实现UserDetailsService接口，或者实现AuthenticationUserDetailsService接口
 *
 * Created by null on 2017/2/17.
 */
public class CasUserDetailsService implements AuthenticationUserDetailsService<CasAssertionAuthenticationToken> {

    private static final Logger log = LoggerFactory.getLogger(CasUserDetailsService.class);

    @Override
    public UserDetails loadUserDetails(CasAssertionAuthenticationToken token) throws UsernameNotFoundException {
        String username = token.getName();
        log.debug("current username [{}]", username);
        // 这里应该查询数据库获取具体的用户信息和权限信息
        Collection<SimpleGrantedAuthority> authorities = new ArrayList<SimpleGrantedAuthority>();
        authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
        return new User(username, username, authorities);
    }
}
