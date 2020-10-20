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
import org.hamcrest.Factory;
import org.junit.Test;

import java.util.Arrays;
import java.util.HashSet;

import static com.hp.autonomy.frontend.configuration.authentication.RoleTest.AuthorizedMatcher.isAuthorizedFor;
import static org.hamcrest.collection.IsCollectionWithSize.hasSize;
import static org.hamcrest.core.IsNot.not;
import static org.junit.Assert.*;

public class RoleTest {

    @Test
    public void testDiamondRoles() throws Exception {
        final Role user = new Role.Builder()
            .setName("user")
            .build();

        final Role admin = new Role.Builder()
            .setName("admin")
            .build();

        final Role useradmin = new Role.Builder()
            .setName("useradmin")
            .build();

        final Role superadmin = new Role.Builder()
            .setName("superadmin")
            .build();

        final Role devil = new Role.Builder()
            .setName("devil")
            .build();

        admin.getParent().add(superadmin);
        admin.getParent().add(useradmin);
        superadmin.getParent().add(devil);
        useradmin.getParent().add(devil);

        assertThat(user.getParent(), hasSize(0));
        assertThat(user.getAncestors(), hasSize(0));
        assertThat(admin.getParent(), hasSize(2));
        assertThat(admin.getAncestors(), hasSize(3));
        assertThat(useradmin.getParent(), hasSize(1));
        assertThat(useradmin.getAncestors(), hasSize(1));
        assertThat(superadmin.getParent(), hasSize(1));
        assertThat(superadmin.getAncestors(), hasSize(1));
        assertThat(devil.getParent(), hasSize(0));
        assertThat(devil.getAncestors(), hasSize(0));
    }

    @Test
    public void testStraightRoles() throws Exception {
        final Role user = new Role.Builder()
            .setName("user")
            .build();

        final Role admin = new Role.Builder()
            .setName("admin")
            .build();

        final Role useradmin = new Role.Builder()
            .setName("useradmin")
            .build();

        useradmin.getParent().add(admin);
        user.getParent().add(useradmin);

        assertThat(user.getParent(), hasSize(1));
        assertThat(user.getAncestors(), hasSize(2));
        assertThat(admin.getParent(), hasSize(0));
        assertThat(admin.getAncestors(), hasSize(0));
        assertThat(useradmin.getParent(), hasSize(1));
        assertThat(useradmin.getAncestors(), hasSize(1));
    }

    @Test
    public void testKiteRoles() throws Exception {
        final Role user = new Role.Builder()
            .setName("user")
            .build();

        final Role superuser = new Role.Builder()
            .setName("superuser")
            .build();

        final Role admin = new Role.Builder()
            .setName("admin")
            .build();

        final Role useradmin = new Role.Builder()
            .setName("useradmin")
            .build();

        final Role superadmin = new Role.Builder()
            .setName("superadmin")
            .build();

        user.getParent().add(superuser);
        superuser.getParent().add(useradmin);
        superuser.getParent().add(admin);
        admin.getParent().add(superadmin);

        assertThat(user.getParent(), hasSize(1));
        assertThat(user.getAncestors(), hasSize(4));
        assertThat(admin.getParent(), hasSize(1));
        assertThat(admin.getAncestors(), hasSize(1));
        assertThat(useradmin.getParent(), hasSize(0));
        assertThat(useradmin.getAncestors(), hasSize(0));
        assertThat(superadmin.getParent(), hasSize(0));
        assertThat(superadmin.getAncestors(), hasSize(0));
        assertThat(superuser.getParent(), hasSize(2));
        assertThat(superuser.getAncestors(), hasSize(3));

        assertEquals("admin", superuser.getParent("admin").getName());
        assertNull(superuser.getParent("ADMIN"));
        assertNull(superuser.getParent("bididibu"));
    }

    @Test
    public void testKiteRolesPrivileges() throws Exception {
        final Role user = new Role.Builder()
            .setName("user")
            .setPrivileges(new HashSet<>(Arrays.asList("read", "execute")))
            .build();

        final Role superuser = new Role.Builder()
            .setName("superuser")
            .setPrivileges(new HashSet<>(Arrays.asList("write", "read", "execute")))
            .build();

        final Role admin = new Role.Builder()
            .setName("admin")
            .setPrivileges(new HashSet<>(Arrays.asList("create", "read", "execute", "write")))
            .build();

        final Role useradmin = new Role.Builder()
            .setName("useradmin")
            .setPrivileges(new HashSet<>(Arrays.asList("create", "read", "execute", "write")))
            .build();

        final Role superadmin = new Role.Builder()
            .setName("superadmin")
            .setPrivileges(new HashSet<>(Arrays.asList("create", "read", "execute", "write", "kill")))
            .build();

        superuser.getParent().add(useradmin);
        superuser.getParent().add(admin);
        admin.getParent().add(superadmin);

        assertThat(user, isAuthorizedFor("read"));
        assertThat(user, not(isAuthorizedFor("create")));
        assertThat(superuser, isAuthorizedFor("read"));
        assertThat(superuser, isAuthorizedFor("write"));
        assertThat(superuser, isAuthorizedFor("execute"));
        assertThat(superuser, isAuthorizedFor("create"));
        assertThat(superuser, isAuthorizedFor("kill"));
        assertThat(useradmin, not(isAuthorizedFor("kill")));
        assertThat(useradmin, isAuthorizedFor("create"));
        assertThat(useradmin, isAuthorizedFor("read"));
        assertThat(useradmin, isAuthorizedFor("execute"));

        assertThat(user, isAuthorizedFor("read", "execute"));
        assertThat(user, not(isAuthorizedFor("read", "execute", "create")));
        assertThat(superuser, isAuthorizedFor("write", "read"));
        assertThat(superuser, not(isAuthorizedFor("create", "read", "execute", "write", "die")));
        assertThat(useradmin, isAuthorizedFor("create", "read", "execute", "write"));
        assertThat(useradmin, not(isAuthorizedFor("create", "kill")));
        assertThat(admin, isAuthorizedFor("read", "execute"));
        assertThat(admin, not(isAuthorizedFor("read", "execute", "die")));
    }

    static class AuthorizedMatcher extends BaseMatcher<Role> {

        private final String[] privileges;

        public AuthorizedMatcher(final String... privilege) {
            this.privileges = privilege;
        }

        @Factory
        static AuthorizedMatcher isAuthorizedFor(final String... privileges) {
            return new AuthorizedMatcher(privileges);
        }

        @Override
        public boolean matches(final Object item) {
            if(!(item instanceof Role)) {
                return false;
            }

            final Role role = (Role) item;

            if(privileges.length == 1) {
                return role.isAuthorized(privileges[0]);
            }
            else {
                return role.isAuthorized(new HashSet<>(Arrays.asList(privileges)));
            }
        }

        @Override
        public void describeTo(final Description description) {
            description.appendText(" a role authorized for ").appendText(Arrays.toString(privileges));
        }
    }
}
