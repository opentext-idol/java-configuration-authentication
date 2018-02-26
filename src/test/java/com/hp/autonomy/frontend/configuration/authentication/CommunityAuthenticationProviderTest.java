/*
 * Copyright 2014-2017 Hewlett-Packard Development Company, L.P.
 * Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
 */

package com.hp.autonomy.frontend.configuration.authentication;

import com.hp.autonomy.frontend.configuration.ConfigService;
import com.hp.autonomy.frontend.configuration.LoginTypes;
import com.hp.autonomy.user.UserRoles;
import com.hp.autonomy.user.UserService;
import java.util.Arrays;
import java.util.HashSet;
import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;

import java.util.Collections;
import java.util.Set;

import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNot.not;
import static org.mockito.AdditionalAnswers.returnsFirstArg;
import static org.mockito.Matchers.anyCollection;
import static org.mockito.Matchers.anySet;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.argThat;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class CommunityAuthenticationProviderTest {

    private static final String APP_ROLE = "APP";
    private static final String DEFAULT_ROLE = "DEFAULT";
    private static final String BOGUS_ROLE = "BOGUS";
    private static final String NEUTRAL_ROLE = "NEUTRAL";

    @SuppressWarnings("rawtypes")
    @Mock
    private CommunityAuthentication authentication;

    @Mock
    private Authentication springAuthentication;

    @Mock
    private TestAuthenticationConfig authenticationConfig;

    @Mock
    private ConfigService<TestAuthenticationConfig> configService;

    @Mock
    private UserService userService;

    @Mock
    private Roles roles;

    @Mock
    private GrantedAuthoritiesMapper grantedAuthoritiesMapper;

    private final Set<String> loginPrivileges = Collections.singleton("LOGIN");

    private CommunityAuthenticationProvider communityAuthenticationProvider;

    private CommunityAuthenticationProvider communityAuthenticationProviderWithDefaultRoles;

    private CommunityAuthenticationProvider communityAuthenticationProviderWithNeutralDefaultRoles;

    @SuppressWarnings("unchecked")
    @Before
    public void setUp() {
        when(authentication.getMethod()).thenReturn("");

        // use not type safe syntax as the usual version won't compile
        Mockito.doReturn(authentication).when(authenticationConfig).getAuthentication();

        when(configService.getConfig()).thenReturn(authenticationConfig);

        when(roles.areRolesAuthorized((Set<String>) argThat(Matchers.hasItem(APP_ROLE)), anySet())).thenReturn(true);
        when(roles.areRolesAuthorized((Set<String>) argThat(Matchers.hasItem(DEFAULT_ROLE)), anySet())).thenReturn(true);
        when(roles.areRolesAuthorized((Set<String>) argThat(Matchers.hasItem(BOGUS_ROLE)), anySet())).thenReturn(false);

        when(springAuthentication.getPrincipal()).thenReturn("username");
        when(springAuthentication.getCredentials()).thenReturn("password");

        when(userService.authenticateUser(anyString(), anyString(), anyString())).thenReturn(true);

        when(grantedAuthoritiesMapper.mapAuthorities(anyCollection())).thenAnswer(returnsFirstArg());

        communityAuthenticationProvider = new CommunityAuthenticationProvider(
                configService,
                userService,
                roles,
                loginPrivileges,
                grantedAuthoritiesMapper
        );

        communityAuthenticationProviderWithDefaultRoles = new CommunityAuthenticationProvider(
                configService,
                userService,
                roles,
                loginPrivileges,
                grantedAuthoritiesMapper,
                Collections.singleton(DEFAULT_ROLE)
        );

        communityAuthenticationProviderWithNeutralDefaultRoles = new CommunityAuthenticationProvider(
                configService,
                userService,
                roles,
                loginPrivileges,
                grantedAuthoritiesMapper,
                new HashSet<>(Arrays.asList(NEUTRAL_ROLE, APP_ROLE))
        );
    }

    @Test
    public void testAuthenticateReturnsNullIfDefaultAuthenticationIsBeingUsed() {
        Mockito.reset(authentication);
        when(authentication.getMethod()).thenReturn(LoginTypes.DEFAULT);

        assertThat(communityAuthenticationProvider.authenticate(springAuthentication), is(nullValue()));
    }

    @Test(expected = BadCredentialsException.class)
    public void testAuthenticateThrowsIfAuthenticateFails() {
        Mockito.reset(userService);
        when(userService.authenticateUser(anyString(), anyString(), anyString())).thenReturn(false);

        communityAuthenticationProvider.authenticate(springAuthentication);
    }

    @Test(expected = BadCredentialsException.class)
    public void testAuthenticateThrowsIfRoleNotAuthorised() {
        final UserRoles userRoles = mock(UserRoles.class);
        when(userRoles.getRoles()).thenReturn(Collections.singletonList(BOGUS_ROLE));

        when(userService.getUser(anyString(), eq(true))).thenReturn(userRoles);

        communityAuthenticationProvider.authenticate(springAuthentication);
    }

    @Test
    public void testAuthenticateReturnsCorrectUser() {
        final UserRoles userRoles = mock(UserRoles.class);
        when(userRoles.getRoles()).thenReturn(Collections.singletonList(APP_ROLE));

        when(userService.getUser(anyString(), eq(true))).thenReturn(userRoles);

        final Authentication authentication = communityAuthenticationProvider.authenticate(springAuthentication);

        //noinspection unchecked
        assertThat((Iterable<GrantedAuthority>) authentication.getAuthorities(), hasItem(new SimpleGrantedAuthority(APP_ROLE)));
    }

    @Test
    public void testAuthenticateReturnsCorrectUserWithDefaultRoles() {
        final UserRoles userRoles = mock(UserRoles.class);
        when(userRoles.getRoles()).thenReturn(Collections.<String>emptyList());

        when(userService.getUser(anyString(), eq(true))).thenReturn(userRoles);

        final Authentication authentication = communityAuthenticationProviderWithDefaultRoles.authenticate(springAuthentication);

        //noinspection unchecked
        assertThat((Iterable<GrantedAuthority>) authentication.getAuthorities(), hasItem(new SimpleGrantedAuthority(DEFAULT_ROLE)));
    }

    @Test
    public void testAuthenticateReturnsCorrectUserWithDefaultRolesAdditively() {
        final UserRoles userRoles = mock(UserRoles.class);
        when(userRoles.getRoles()).thenReturn(Collections.singletonList(NEUTRAL_ROLE));

        when(userService.getUser(anyString(), eq(true))).thenReturn(userRoles);

        final Authentication authentication = communityAuthenticationProviderWithDefaultRoles.authenticate(springAuthentication);

        //noinspection unchecked
        final Iterable<GrantedAuthority> authorities = (Iterable<GrantedAuthority>) authentication.getAuthorities();
        assertThat(authorities, hasItem(new SimpleGrantedAuthority(DEFAULT_ROLE)));
        assertThat(authorities, hasItem(new SimpleGrantedAuthority(NEUTRAL_ROLE)));
    }

    @Test
    public void testAuthenticateAllowsDecreasingRoles() {
        // Testing that we can override generous defaults by having just-enough permissions on the user, e.g. if we
        //   wanted the default Find user to have FindUser,FindBI but a particular user to only have FindUser
        //   without FindBI.
        final UserRoles userRoles = mock(UserRoles.class);
        when(userRoles.getRoles()).thenReturn(Collections.singletonList(APP_ROLE));

        when(userService.getUser(anyString(), eq(true))).thenReturn(userRoles);

        final Authentication authentication = communityAuthenticationProviderWithNeutralDefaultRoles.authenticate(springAuthentication);

        //noinspection unchecked
        final Iterable<GrantedAuthority> authorities = (Iterable<GrantedAuthority>) authentication.getAuthorities();
        assertThat(authorities, not(hasItem(new SimpleGrantedAuthority(NEUTRAL_ROLE))));
        assertThat(authorities, not(hasItem(new SimpleGrantedAuthority(DEFAULT_ROLE))));
        assertThat(authorities, hasItem(new SimpleGrantedAuthority(APP_ROLE)));
    }

    private interface TestAuthenticationConfig extends AuthenticationConfig<TestAuthenticationConfig>{}

}