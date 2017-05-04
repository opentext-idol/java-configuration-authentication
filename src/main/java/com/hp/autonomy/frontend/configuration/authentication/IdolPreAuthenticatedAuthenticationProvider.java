/*
 * Copyright 2014-2017 Hewlett-Packard Development Company, L.P.
 * Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
 */

package com.hp.autonomy.frontend.configuration.authentication;

import com.hp.autonomy.user.UserRoles;
import com.hp.autonomy.user.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import java.util.Collection;
import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
public class IdolPreAuthenticatedAuthenticationProvider implements AuthenticationProvider {

    private final UserService userService;
    private final GrantedAuthoritiesMapper authoritiesMapper;
    private final Set<String> preAuthenticatedRoles;

    public IdolPreAuthenticatedAuthenticationProvider(
            final UserService userService,
            final GrantedAuthoritiesMapper authoritiesMapper,
            final Set<String> preAuthenticatedRoles
    ) {
        this.userService = userService;
        this.authoritiesMapper = authoritiesMapper;
        this.preAuthenticatedRoles = preAuthenticatedRoles;
    }

    @Override
    public Authentication authenticate(final Authentication authentication) throws AuthenticationException {
        final Object principal = authentication.getPrincipal();

        if (principal == null) {
            throw new BadCredentialsException("Principal not supplied");
        }

        final String username = principal.toString().toLowerCase();

        final UserRoles user = userService.getUser(username, true);

        final Collection<SimpleGrantedAuthority> grantedAuthorities = preAuthenticatedRoles.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toSet());

        final CommunityPrincipal communityPrincipal = new CommunityPrincipal(user.getUid(), username, user.getSecurityInfo(), Collections.emptySet());
        final Collection<? extends GrantedAuthority> authorities = authoritiesMapper.mapAuthorities(grantedAuthorities);
        return new UsernamePasswordAuthenticationToken(communityPrincipal, null, authorities);
    }

    @Override
    public boolean supports(final Class<?> authentication) {
        return authentication.equals(PreAuthenticatedAuthenticationToken.class);
    }

}
