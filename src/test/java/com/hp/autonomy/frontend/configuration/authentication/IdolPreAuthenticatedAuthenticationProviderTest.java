/*
 * (c) Copyright 2014-2017 Micro Focus or one of its affiliates.
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

import com.autonomy.aci.client.services.AciErrorException;
import com.hp.autonomy.user.UserRoles;
import com.hp.autonomy.user.UserService;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import java.security.Principal;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.stream.Collectors;

import static org.hamcrest.Matchers.hasSize;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class IdolPreAuthenticatedAuthenticationProviderTest {
    private static final String SAMPLE_USER = "some_user";

    private AuthenticationProvider authenticationProvider;

    @Mock
    private UserService userService;

    @Mock
    private GrantedAuthoritiesMapper authoritiesMapper;

    @Mock
    private Authentication authentication;

    @Mock
    private Principal principal;

    @SuppressWarnings("unchecked")
    @Before
    public void setUp() {
        when(authentication.getPrincipal()).thenReturn(principal);
        when(principal.toString()).thenReturn(SAMPLE_USER);

        when(authoritiesMapper.mapAuthorities(any())).thenAnswer(invocation -> ((Collection<? extends GrantedAuthority>) invocation.getArgumentAt(0, Collection.class))
                .stream()
                .map(x -> mock(GrantedAuthority.class))
                .collect(Collectors.toList()));

        authenticationProvider = new IdolPreAuthenticatedAuthenticationProvider(
                userService,
                authoritiesMapper,
                new HashSet<>(Arrays.asList("SomeRole", "SomeOtherRole"))
        );
    }

    @Test
    public void authenticateWithExistingUser() {
        when(userService.getUser(SAMPLE_USER, true)).thenReturn(new UserRoles(SAMPLE_USER));
        final Authentication communityAuthentication = authenticationProvider.authenticate(authentication);
        assertTrue(communityAuthentication.isAuthenticated());
        assertThat(communityAuthentication.getAuthorities(), hasSize(2));
    }

    @Test(expected = BadCredentialsException.class)
    public void authenticateWithNoPrincipal() {
        when(authentication.getPrincipal()).thenReturn(null);
        authenticationProvider.authenticate(authentication);
    }

    @Test(expected = AciErrorException.class)
    public void communityError() {
        when(userService.getUser(SAMPLE_USER, true)).thenThrow(new AciErrorException());
        authenticationProvider.authenticate(authentication);
    }

    @Test
    public void supports() {
        assertTrue(authenticationProvider.supports(PreAuthenticatedAuthenticationToken.class));
        assertFalse(authenticationProvider.supports(UsernamePasswordAuthenticationToken.class));
    }
}
