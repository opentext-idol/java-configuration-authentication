/*
 * Copyright 2014-2015 Hewlett-Packard Development Company, L.P.
 * Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
 */

import com.hp.autonomy.frontend.configuration.AuthenticationConfig;
import com.hp.autonomy.frontend.configuration.BCryptUsernameAndPassword;
import com.hp.autonomy.frontend.configuration.ConfigService;
import com.hp.autonomy.frontend.configuration.LoginTypes;
import com.hp.autonomy.frontend.configuration.SingleUserAuthentication;
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
        final com.hp.autonomy.frontend.configuration.Authentication<?> configAuthentication = configService.getConfig().getAuthentication();

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
