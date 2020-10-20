/*
 * (c) Copyright 2014-2015 Micro Focus or one of its affiliates.
 *
 * Licensed under the MIT License (the "License"); you may not use this file
 * except in compliance with the License.
 *
 * The only warranties for products and services of Micro Focus and its affiliates
 * and licensors ("Micro Focus") are as may be set forth in the express warranty
 * statements accompanying such products and services. Nothing herein should be
 * construed as constituting an additional warranty. Micro Focus shall not be
 * liable for technical or editorial errors or omissions contained herein. The
 * information contained herein is subject to change without notice.
 */
package com.hp.autonomy.frontend.configuration.authentication;

import com.hp.autonomy.frontend.configuration.ConfigService;
import com.hp.autonomy.frontend.configuration.LoginTypes;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Arrays;

public class DefaultLoginAuthenticationProvider implements AuthenticationProvider {

    private final String roleDefault;

    private final ConfigService<? extends AuthenticationConfig<?>> configService;

    public DefaultLoginAuthenticationProvider(final ConfigService<? extends AuthenticationConfig<?>> configService, final String roleDefault) {
        this.roleDefault = roleDefault;
        this.configService = configService;
    }

    @Override
    public Authentication authenticate(final Authentication authentication) throws AuthenticationException {
        final com.hp.autonomy.frontend.configuration.authentication.Authentication<?> authenticationConfig = configService.getConfig().getAuthentication();

        if(!LoginTypes.DEFAULT.equalsIgnoreCase(authenticationConfig.getMethod())) {
            return null;
        }

        final UsernameAndPassword defaultLogin = authenticationConfig.getDefaultLogin();

        final String username = authentication.getName();
        final String password = authentication.getCredentials().toString();

        if(defaultLogin.getUsername().equals(username) && defaultLogin.getPassword().equals(password)) {
            return new UsernamePasswordAuthenticationToken(username, password, Arrays.asList(new SimpleGrantedAuthority(roleDefault)));
        }
        else {
            throw new BadCredentialsException("Access is denied");
        }
    }

    @Override
    public boolean supports(final Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class == authentication;
    }
}
