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

import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;
import java.util.HashSet;

import static com.hp.autonomy.frontend.configuration.authentication.RolesTest.RolesAuthorizedMatcher.areAuthorizedFor;
import static com.hp.autonomy.frontend.configuration.authentication.RolesTest.RolesWithRoles.hasRoles;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNot.not;
import static org.junit.Assert.assertThat;

public class RolesTest {

    private Roles roles;

    @Before
    public void setUp() {
        final Role user = new Role.Builder()
            .setName("user")
            .setPrivileges(new HashSet<>(Arrays.asList("read", "execute")))
            .build();

        final Role superuser = new Role.Builder()
            .setName("superuser")
            .setPrivileges(new HashSet<>(Arrays.asList("read", "execute", "write")))
            .build();

        final Role admin = new Role.Builder()
            .setName("admin")
            .setPrivileges(new HashSet<>(Arrays.asList("read", "execute", "write", "create", "delete")))
            .build();

        final Role useradmin = new Role.Builder()
            .setName("useradmin")
            .setPrivileges(new HashSet<>(Arrays.asList("read", "execute", "create", "destroy")))
            .build();

        final Role loner = new Role.Builder()
            .setName("loner")
            .setPrivileges(new HashSet<>(Arrays.asList("think", "meditate", "thinkagain", "shout")))
            .build();

        user.getParent().add(superuser);
        superuser.getParent().add(useradmin);
        superuser.getParent().add(admin);

        roles = new Roles(Arrays.asList(user, superuser, admin, useradmin, loner));
    }

    @Test
    public void testGetRole(){
        assertThat(this.roles.getRole("user").getName(), is("user"));
        assertThat(this.roles.getRole("aaaaa"), is(nullValue()));
    }

    @Test
    public void testIsAuthorized(){
        assertThat(this.roles, areAuthorizedFor("destroy"));
        assertThat(this.roles, areAuthorizedFor("execute"));
        assertThat(this.roles, not(areAuthorizedFor("kill")));
    }

    @Test
    public void testAreRolesAuthorized(){
        assertThat(this.roles, hasRoles("user", "superuser").authorizedForPrivileges("execute"));
        assertThat(this.roles, hasRoles("user", "superuser").authorizedForPrivileges("write"));

        assertThat(this.roles, not(hasRoles("loner").authorizedForPrivileges("destroy")));

        assertThat(this.roles, hasRoles("user", "loner").authorizedForPrivileges("execute", "shout"));
        assertThat(this.roles, hasRoles("user", "admin").authorizedForPrivileges("execute", "create"));
        assertThat(this.roles, hasRoles("loner").authorizedForPrivileges("think", "meditate", "thinkagain", "shout"));

        assertThat(this.roles, not(hasRoles("user", "admin").authorizedForPrivileges("think", "meditate", "thinkagain", "shout")));
        assertThat(this.roles, not(hasRoles("user", "superuser").authorizedForPrivileges("execute", "shout")));
    }

    static class RolesWithRoles {

        private final String[] roles;

        private RolesWithRoles(final String... roles) {
            this.roles = roles;
        }

        static RolesWithRoles hasRoles(final String... roles) {
            return new RolesWithRoles(roles);
        }

        RolesWithPrivileges authorizedForPrivileges(final String... privileges) {
            return new RolesWithPrivileges(roles, privileges);
        }

    }

    private static class RolesWithPrivileges extends BaseMatcher<Roles> {

        private final String[] roles;
        private final String[] privileges;

        RolesWithPrivileges(final String[] roles, final String[] privileges) {
            this.roles = roles;
            this.privileges = privileges;
        }

        @Override
        public boolean matches(final Object item) {
            if (!(item instanceof Roles)) {
                return false;
            }

            final Roles roles = (Roles) item;

            return roles.areRolesAuthorized(new HashSet<>(Arrays.asList(this.roles)), new HashSet<>(Arrays.asList(privileges)));
        }

        @Override
        public void describeTo(final Description description) {
            description.appendText(" roles containing ").appendText(Arrays.toString(roles)).appendText(" with privileges ").appendText(Arrays.toString(privileges));
        }
    }

    static class RolesAuthorizedMatcher extends BaseMatcher<Roles> {

        private final String privilege;

        public RolesAuthorizedMatcher(final String privilege) {
            this.privilege = privilege;
        }

        public static RolesAuthorizedMatcher areAuthorizedFor(final String privilege) {
            return new RolesAuthorizedMatcher(privilege);
        }

        @Override
        public boolean matches(final Object item) {
            if (!(item instanceof Roles)) {
                return false;
            }

            final Roles roles = (Roles) item;

            return roles.isAuthorized(privilege);
        }

        @Override
        public void describeTo(final Description description) {
            description.appendText(" a set of roles authorized for ").appendText(privilege);
        }
    }
}
