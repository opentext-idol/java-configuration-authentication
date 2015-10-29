/*
 * Copyright 2014-2015 Hewlett-Packard Development Company, L.P.
 * Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
 */

package com.hp.autonomy.frontend.configuration.authentication;

import org.junit.Test;

import java.util.Arrays;
import java.util.HashSet;

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

        assertEquals(0, user.getParent().size());
        assertEquals(0, user.getAncestors().size());
        assertEquals(2, admin.getParent().size());
        assertEquals(3, admin.getAncestors().size());
        assertEquals(1, useradmin.getParent().size());
        assertEquals(1, useradmin.getAncestors().size());
        assertEquals(1, superadmin.getParent().size());
        assertEquals(1, superadmin.getAncestors().size());
        assertEquals(0, devil.getParent().size());
        assertEquals(0, devil.getAncestors().size());
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

        assertEquals(1, user.getParent().size());
        assertEquals(2, user.getAncestors().size());
        assertEquals(0, admin.getParent().size());
        assertEquals(0, admin.getAncestors().size());
        assertEquals(1, useradmin.getParent().size());
        assertEquals(1, useradmin.getAncestors().size());
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

        assertEquals(1, user.getParent().size());
        assertEquals(4, user.getAncestors().size());
        assertEquals(1, admin.getParent().size());
        assertEquals(1, admin.getAncestors().size());
        assertEquals(0, useradmin.getParent().size());
        assertEquals(0, useradmin.getAncestors().size());
        assertEquals(0, superadmin.getParent().size());
        assertEquals(0, superadmin.getAncestors().size());
        assertEquals(2, superuser.getParent().size());
        assertEquals(3, superuser.getAncestors().size());

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

        assertTrue(user.isAuthorized("read"));
        assertFalse(user.isAuthorized("create"));
        assertTrue(superuser.isAuthorized("read"));
        assertTrue(superuser.isAuthorized("write"));
        assertTrue(superuser.isAuthorized("execute"));
        assertTrue(superuser.isAuthorized("create"));
        assertTrue(superuser.isAuthorized("kill"));
        assertFalse(useradmin.isAuthorized("kill"));
        assertTrue(useradmin.isAuthorized("create"));
        assertTrue(useradmin.isAuthorized("read"));
        assertTrue(useradmin.isAuthorized("execute"));

        assertTrue(user.isAuthorized(new HashSet<>(Arrays.asList("read", "execute"))));
        assertFalse(user.isAuthorized(new HashSet<>(Arrays.asList("read", "execute", "create"))));
        assertTrue(superuser.isAuthorized(new HashSet<>(Arrays.asList("write", "read"))));
        assertFalse(superuser.isAuthorized(new HashSet<>(Arrays.asList("create", "read", "execute", "write", "die"))));
        assertTrue(useradmin.isAuthorized(new HashSet<>(Arrays.asList("create", "read", "execute", "write"))));
        assertFalse(useradmin.isAuthorized(new HashSet<>(Arrays.asList("create", "kill"))));
        assertTrue(admin.isAuthorized(new HashSet<>(Arrays.asList("read", "execute"))));
        assertFalse(admin.isAuthorized(new HashSet<>(Arrays.asList("read", "execute", "die"))));
    }
}