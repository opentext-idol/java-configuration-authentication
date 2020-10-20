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
import org.mindrot.jbcrypt.BCrypt;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Arrays;

public class SingleUserAuthenticationProvider implements AuthenticationProvider {

    private final String roleAdmin;

    private final ConfigService<? extends AuthenticationConfig<?>> configService;

    public SingleUserAuthenticationProvider(final ConfigService<? extends AuthenticationConfig<?>> configService, final String roleAdmin) {
        this.configService = configService;
        this.roleAdmin = roleAdmin;
    }

    @Override
    public Authentication authenticate(final Authentication authentication) throws AuthenticationException {
        final com.hp.autonomy.frontend.configuration.authentication.Authentication<?> configAuthentication = configService.getConfig().getAuthentication();

        if(!(configAuthentication instanceof SingleUserAuthentication) || LoginTypes.DEFAULT.equalsIgnoreCase(configAuthentication.getMethod())) {
            return null;
        }

        final SingleUserAuthentication singleUserAuthentication = (SingleUserAuthentication) configAuthentication;
        final BCryptUsernameAndPassword singleUser = singleUserAuthentication.getSingleUser();

        final String username = singleUser.getUsername();
        final String hashedPassword = singleUser.getHashedPassword();
        final String providedPassword = authentication.getCredentials().toString();

        if(authentication.getName().equals(username) && BCrypt.checkpw(providedPassword, hashedPassword)) {
            return new UsernamePasswordAuthenticationToken(username, providedPassword, Arrays.asList(new SimpleGrantedAuthority(roleAdmin)));
        }
        else {
            throw new BadCredentialsException("Bad credentials");
        }
    }

    @Override
    public boolean supports(final Class<?> authentication) {
        return authentication == UsernamePasswordAuthenticationToken.class;
    }
}
