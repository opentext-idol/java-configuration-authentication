/*
 * Copyright 2014-2017 Open Text.
 *
 * Licensed under the MIT License (the "License"); you may not use this file
 * except in compliance with the License.
 *
 * The only warranties for products and services of Open Text and its affiliates
 * and licensors ("Open Text") are as may be set forth in the express warranty
 * statements accompanying such products and services. Nothing herein should be
 * construed as constituting an additional warranty. Open Text shall not be
 * liable for technical or editorial errors or omissions contained herein. The
 * information contained herein is subject to change without notice.
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
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
public class IdolPreAuthenticatedAuthenticationProvider implements AuthenticationProvider {

    private final UserService userService;
    private final GrantedAuthoritiesMapper authoritiesMapper;
    private final Set<String> preAuthenticatedRoles;
    private final boolean passwordRequired;

    public IdolPreAuthenticatedAuthenticationProvider(
            final UserService userService,
            final GrantedAuthoritiesMapper authoritiesMapper,
            final Set<String> preAuthenticatedRoles,
            final boolean passwordRequired
    ) {
        this.userService = userService;
        this.authoritiesMapper = authoritiesMapper;
        this.preAuthenticatedRoles = preAuthenticatedRoles;
        this.passwordRequired = passwordRequired;
    }

    @Override
    public Authentication authenticate(final Authentication authentication) throws AuthenticationException {
        final Object principal = authentication.getPrincipal();

        if (principal == null) {
            throw new BadCredentialsException("Principal not supplied");
        }

        final String username = principal.toString().toLowerCase();

        // if a password would be required, don't ask for security info
        final UserRoles user = passwordRequired ?
            userService.getUser(username, true) :
            userService.getUser(username, true, null);
        final Set<String> roleNames = preAuthenticatedRoles.isEmpty() ?
            new HashSet<>(user.getRoles()) :
            preAuthenticatedRoles;

        final Collection<SimpleGrantedAuthority> grantedAuthorities = roleNames.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toSet());

        final CommunityPrincipal communityPrincipal = new CommunityPrincipal(user.getUid(), username, user.getSecurityInfo(), roleNames, user.getFields());
        final Collection<? extends GrantedAuthority> authorities = authoritiesMapper.mapAuthorities(grantedAuthorities);
        return new UsernamePasswordAuthenticationToken(communityPrincipal, null, authorities);
    }

    @Override
    public boolean supports(final Class<?> authentication) {
        return authentication.equals(PreAuthenticatedAuthenticationToken.class);
    }

}
