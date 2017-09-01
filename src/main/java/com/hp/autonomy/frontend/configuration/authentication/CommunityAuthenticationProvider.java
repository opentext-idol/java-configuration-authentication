/*
 * Copyright 2014-2015 Hewlett-Packard Development Company, L.P.
 * Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
 */

package com.hp.autonomy.frontend.configuration.authentication;

import com.autonomy.aci.client.services.AciErrorException;
import com.autonomy.aci.client.services.AciServiceException;
import com.hp.autonomy.frontend.configuration.ConfigService;
import com.hp.autonomy.frontend.configuration.LoginTypes;
import com.hp.autonomy.user.UserRoles;
import com.hp.autonomy.user.UserService;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * A Spring Security {@link AuthenticationProvider} backed by IDOL community.
 *
 * The CommunityAuthenticationProvider optionally takes a set of default roles. If this set is non empty, users will be
 * granted these roles by the application. Otherwise, a {@link BadCredentialsException} will be thrown.
 */
public class CommunityAuthenticationProvider implements AuthenticationProvider {
    private final ConfigService<? extends AuthenticationConfig<?>> configService;
    private final UserService userService;
    private final Roles roles;
    private final Set<String> loginPrivileges;
    private final GrantedAuthoritiesMapper authoritiesMapper;
    private final Set<String> defaultRoles;

    /**
     * Creates a new CommunityAuthenticationProvider with an empty set of default roles
     * @param configService The configuration service used for authentication
     * @param userService The user service used to interact with Community
     * @param roles The list of Community roles used by the application
     * @param loginPrivileges The list of privileges a role must have to be allowed to log in to the application
     * @param authoritiesMapper Mapper used to convert Community roles into GrantedAuthorities
     */
    public CommunityAuthenticationProvider(
        final ConfigService<? extends AuthenticationConfig<?>> configService,
        final UserService userService,
        final Roles roles,
        final Set<String> loginPrivileges,
        final GrantedAuthoritiesMapper authoritiesMapper
    ) {
        this(configService, userService, roles, loginPrivileges,  authoritiesMapper, Collections.<String>emptySet());
    }

    /**
     * Creates a new CommunityAuthenticationProvider
     *
     * @param configService     The configuration service used for authentication
     * @param userService       The user service used to interact with Community
     * @param roles             The list of Community roles used by the application
     * @param loginPrivileges   The list of privileges a role must have to be allowed to log in to the application
     * @param authoritiesMapper Mapper used to convert Community roles into GrantedAuthorities
     * @param defaultRoles Set of default roles to apply if no application roles are found
     */
    public CommunityAuthenticationProvider(
        final ConfigService<? extends AuthenticationConfig<?>> configService,
        final UserService userService,
        final Roles roles,
        final Set<String> loginPrivileges,
        final GrantedAuthoritiesMapper authoritiesMapper,
        final Set<String> defaultRoles
    ) {
        this.configService = configService;
        this.userService = userService;
        this.roles = roles;
        this.loginPrivileges = loginPrivileges;
        this.authoritiesMapper = authoritiesMapper;
        this.defaultRoles = defaultRoles;
    }

    @Override
    public Authentication authenticate(final Authentication authentication) throws AuthenticationException {
        final com.hp.autonomy.frontend.configuration.authentication.Authentication<?> authenticationConfig = configService.getConfig().getAuthentication();
        final String authenticationMethod = authenticationConfig.getMethod();

        if (!(authenticationConfig instanceof CommunityAuthentication) || LoginTypes.DEFAULT.equals(authenticationMethod)) {
            return null;
        }

        final String username = authentication.getName();
        final String password = authentication.getCredentials().toString();

        try {
            final boolean isAuthenticated = userService.authenticateUser(username, password, authenticationMethod);

            if (!isAuthenticated) {
                throw new BadCredentialsException("Bad credentials");
            }

            final UserRoles userRoles = userService.getUser(username, true);
            Set<String> roleNames = new HashSet<>(userRoles.getRoles());

            if (!roles.areRolesAuthorized(roleNames, loginPrivileges)) {
                // if we have default roles, grant the user the default roles
                if(!defaultRoles.isEmpty()) {
                    roleNames = defaultRoles;

                    // check that the default role names make sense
                    if (!roles.areRolesAuthorized(roleNames, loginPrivileges)) {
                        throw new BadCredentialsException("Bad credentials");
                    }
                }
                else {
                    throw new BadCredentialsException("Bad credentials");
                }
            }

            final Collection<GrantedAuthority> grantedAuthorities = roleNames.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());

            final Collection<? extends GrantedAuthority> mappedAuthorities = authoritiesMapper.mapAuthorities(grantedAuthorities);

            return new UsernamePasswordAuthenticationToken(new CommunityPrincipal(userRoles.getUid(), username, userRoles.getSecurityInfo(), roleNames, userRoles.getFields()), password, mappedAuthorities);
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
        return Objects.equals(authenticationClass, UsernamePasswordAuthenticationToken.class);
    }
}
