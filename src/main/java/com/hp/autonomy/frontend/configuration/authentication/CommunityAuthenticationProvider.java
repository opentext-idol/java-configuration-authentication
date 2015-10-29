/*
 * Copyright 2014-2015 Hewlett-Packard Development Company, L.P.
 * Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
 */

package com.hp.autonomy.frontend.abc.authentication;

import com.autonomy.aci.client.services.AciErrorException;
import com.autonomy.aci.client.services.AciServiceException;
import com.autonomy.login.role.Roles;
import com.autonomy.user.admin.UserAdmin;
import com.autonomy.user.admin.dto.UserRoles;
import com.google.common.base.Function;
import com.google.common.collect.Lists;
import com.hp.autonomy.frontend.configuration.AuthenticationConfig;
import com.hp.autonomy.frontend.configuration.CommunityAuthentication;
import com.hp.autonomy.frontend.configuration.ConfigService;
import com.hp.autonomy.frontend.configuration.LoginTypes;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * A Spring Security {@link org.springframework.security.authentication.AuthenticationProvider} backed by IDOL community.
 */
public class CommunityAuthenticationProvider implements AuthenticationProvider {
    private final ConfigService<? extends AuthenticationConfig<?>> configService;
    private final UserAdmin userAdmin;
    private final Roles roles;
    private final Set<String> loginPrivileges;
    private final GrantedAuthoritiesMapper authoritiesMapper;

    public CommunityAuthenticationProvider(
            final ConfigService<? extends AuthenticationConfig<?>> configService,
            final UserAdmin userAdmin,
            final Roles roles,
            final Set<String> loginPrivileges,
            final GrantedAuthoritiesMapper authoritiesMapper
    ) {
        this.configService = configService;
        this.userAdmin = userAdmin;
        this.roles = roles;
        this.loginPrivileges = loginPrivileges;
        this.authoritiesMapper = authoritiesMapper;
    }

    @Override
    public Authentication authenticate(final Authentication authentication) throws AuthenticationException {
        final com.hp.autonomy.frontend.configuration.Authentication<?> authenticationConfig = configService.getConfig().getAuthentication();
        final String authenticationMethod = authenticationConfig.getMethod();

        if (!(authenticationConfig instanceof CommunityAuthentication) || LoginTypes.DEFAULT.equals(authenticationMethod)) {
            return null;
        }

        final String username = authentication.getName();
        final String password = authentication.getCredentials().toString();

        try {
            final boolean isAuthenticated = userAdmin.authenticateUser(username, password, authenticationMethod);

            if (!isAuthenticated) {
                throw new BadCredentialsException("Bad credentials");
            }

            final UserRoles userRoles = userAdmin.getUser(username);

            if (!roles.areRolesAuthorized(new HashSet<>(userRoles.getRoles()), loginPrivileges)) {
                throw new BadCredentialsException("Bad credentials");
            }

            final Collection<? extends GrantedAuthority> mappedAuthorities = authoritiesMapper.mapAuthorities(Lists.transform(userRoles.getRoles(), new Function<String, GrantedAuthority>() {
                @Override
                public GrantedAuthority apply(final String role) {
                    return new SimpleGrantedAuthority(role);
                }
            }));

            return new UsernamePasswordAuthenticationToken(username, password, mappedAuthorities);
        } catch (final AciErrorException aciError) {
            // This should not happen
            throw new InternalAuthenticationServiceException("An ACI error occurred while attempting to authenticate", aciError);
        } catch (final AciServiceException serviceError) {
            // This will happen if community is down
            throw new InternalAuthenticationServiceException("An error occurred while contacting community", serviceError);
        }
    }

    @Override
    public boolean supports(final Class<?> authenticationClass) {
        return authenticationClass == UsernamePasswordAuthenticationToken.class;
    }
}
